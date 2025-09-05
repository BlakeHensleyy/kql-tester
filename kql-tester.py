import os
import sys
import argparse
import pandas as pd
import re
import yaml
from datetime import timedelta
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential

# Configuration: Execution time thresholds (in seconds)
EXECUTION_TIME_THRESHOLDS = {
    "pass": 60.0,    # Under 1 minute = PASS
    "warn": 120.0    # 1-2 minutes = WARN, over 2 minutes = FAIL
}

# Configuration: Result count thresholds by severity
ALERT_BACK_SEARCH_THRESHOLDS = {
    "Informational": 60,
    "Low": 30,
    "Medium": 15,
    "High": 5
}

QUERY_BACK_SEARCH_THRESHOLDS = {
    "Informational": 80,
    "Low": 40,
    "Medium": 20,
    "High": 8
}

# Configuration: Results diff threshold
RESULTS_DIFF_MULTIPLIER = 2    # Fail if new query has over 2X results compared to source branch

test_descriptions = """
Available Test Types:
  query-back-search        - Tests if a query returns too many results over a given time period.
                            Uses severity-based thresholds to determine pass/fail.
                            
  alert-back-search        - Tests if a detection rule has generated too many alerts.
                            Queries AlertInfo table to count alerts by rule name.
                            
  results-diff            - Compares query results between current branch and source branch.
                            Fails if current query returns significantly more results.
                            
  execution-efficiency    - Can be added as suffix to any test (e.g., query-back-search-execution-efficiency).
                            Tests query performance against execution time thresholds.
"""

parser = argparse.ArgumentParser(
    description="KQL Query Testing Tool for Microsoft Sentinel",
    epilog=test_descriptions,
    formatter_class=argparse.RawDescriptionHelpFormatter
)
parser.add_argument("-d", "--YamlPath", dest="YamlPath", required=True, help="YAML file containing the query field.")
parser.add_argument("-tF", "--TimeFromFile", action=argparse.BooleanOptionalAction, help="To use the query time in the YAML file.")
parser.add_argument("-t", "--QueryTime", dest="QueryTime", help="Provide the searchback time if TimeFromFile set to false. Provide in this format: 1d, 2h, 5m")
parser.add_argument("-tT", "--TestType", dest="TestType", required=True, help="Test type: query-back-search, alert-back-search, results-diff, execution-efficiency. Add '-execution-efficiency' to any test for performance testing.")
parser.add_argument("-iD", "--IncludeData", dest="IncludeData", nargs="?", const=10, type=int, help="Include data in the output YAML file. Optionally specify the maximum number of rows to include (default is 10).")
parser.add_argument("-sB", "--SourceBranch", dest="SourceBranch", default="main", help="Source branch for results-diff test type. Default is 'main'.")
parser.add_argument("-o", "--OutputPath", dest="OutputPath", default="test_results/summary.yml", help="Path to the output YAML file.")

args = parser.parse_args()

yaml_file_path = args.YamlPath
time_from_file = args.TimeFromFile
query_time = args.QueryTime
test_type = args.TestType
include_data = args.IncludeData
source_branch = args.SourceBranch
output_file_path = args.OutputPath
test_result = "None"

# Validate SourceBranch is only used with results-diff
if not test_type.startswith("results-diff") and args.SourceBranch != "main":
    print("::warning::SourceBranch argument is only applicable for results-diff test type. Ignoring.")

# Determine if execution efficiency testing is enabled
test_execution_efficiency = test_type.endswith("-execution-efficiency")
if test_execution_efficiency:
    # Remove the execution-efficiency suffix to get the base test type
    base_test_type = test_type.replace("-execution-efficiency", "")
else:
    base_test_type = test_type

# Function to translate custom time format to timedelta arguments
def translate_custom_duration(period):
    pattern = r'(\d+d)?\s*(\d+h)?\s*(\d+m)?'
    match = re.match(pattern, period)
    if not match:
        raise ValueError(f"Invalid time format: {period}")
    days = int(match.group(1)[:-1]) if match.group(1) else 0
    hours = int(match.group(2)[:-1]) if match.group(2) else 0
    minutes = int(match.group(3)[:-1]) if match.group(3) else 0
    return f"days={days}, hours={hours}, minutes={minutes}"

# Function to convert timestamps to string for YAML serialization
def convert_timestamps(data):
    if isinstance(data, list):
        return [convert_timestamps(item) for item in data]
    elif isinstance(data, dict):
        return {key: convert_timestamps(value) for key, value in data.items()}
    elif isinstance(data, pd.Timestamp):
        return data.isoformat()
    else:
        return data

# Custom YAML dumper to improve formatting
class CustomDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(CustomDumper, self).increase_indent(flow, False)

# Custom YAML presenter to make sure the query field is readable. Still doesn't work perfectly.
def str_presenter(dumper, data):
    if '\n' in data:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)

yaml.add_representer(str, str_presenter)

# Function to update test result based on precedence. This prevents WARN/FAIL from being overwritten.
precedence = {"PASS": 1, "WARN": 2, "FAIL": 3, "unknown": 0}
def update_test_result(current_result, new_result):
    if precedence[new_result.split(":")[0]] > precedence[current_result.split(":")[0]]:
        return new_result
    return current_result

# Initialize the Azure Monitor Logs client.
credential = DefaultAzureCredential()
client = LogsQueryClient(credential)

logs_workspace_id = os.getenv('LOGS_WORKSPACE_ID')
if not logs_workspace_id:
    print("::error::Environment variable LOGS_WORKSPACE_ID must be set. Please configure it in your environment.")
    sys.exit(1)

# Process the YAML file
print(f"Processing file: {yaml_file_path}")

# Check that the YAML path is legit.
try:
    with open(yaml_file_path, 'r', encoding='utf-8') as file:
        yaml_data = yaml.safe_load(file)
except FileNotFoundError:
    print(f"File not found: {yaml_file_path}")
    sys.exit(1)
except yaml.YAMLError:
    print(f"Error decoding YAML in file: {yaml_file_path}")
    sys.exit(1)

# Extract the query and rule_name from the YAML data
try:
    query = yaml_data.get('query', None)
    rule_name = yaml_data.get('name', None)
    severity = yaml_data.get('severity', None)
    if query is None:
        raise KeyError("Error: 'query' not found in YAML file")
    if rule_name is None:
        raise KeyError("Error: 'name' not found in YAML file")
    if severity is None:
        raise KeyError("Error: 'severity' not found in YAML file")
except KeyError as e:
    print(e)
    sys.exit(1)

# Determine the query time
if time_from_file:
    if yaml_data['kind'] != "NRT":
        try:
            query_time = yaml_data.get('queryPeriod', None)
            if query_time is not None:
                query_time = translate_custom_duration(query_time)
            else:
                raise KeyError("Error: 'queryPeriod' not found in YAML file")
        except KeyError as e:
            print(e)
            sys.exit(1)
    else:
        # Set query time if the rule is NRT instead of Scheduled
        query_time = "15m" # The time is fairly low because NRT runs against one log at a time.
        query_time = translate_custom_duration(query_time)
        print(f"Error: This rule is NRT instead of Scheduled. The query_time has been changed to {query_time}.")
else:
    if query_time is not None:
        query_time = translate_custom_duration(query_time)
    else:
        print("Error: Query time must be provided if TimeFromFile is set to False.")
        sys.exit(1)

# If the test is alert-back-search, replace the query to find the number of alerts in the alotted time.
if test_type.startswith("alert-back-search"):
    if not include_data:
        include_data = True
        print("--IncludeData option set to true because alert-back-search is used.")
    query = f'AlertInfo | where Title == "{rule_name}" | summarize count() by Title'

# Make the request and format the results.
try:
    kwargs = eval(f"dict({query_time})")
    time_delta = timedelta(**kwargs)
    # The timespan in the API request overrides any timeGenerated values in the KQL.
    response = client.query_workspace(
        workspace_id=logs_workspace_id,
        query=query,
        timespan=time_delta,
        include_statistics=True
    )

    if response.status == LogsQueryStatus.SUCCESS:
        data = response.tables
        statistics = response.statistics
        test_result = "PASS"
    elif response.status == LogsQueryStatus.PARTIAL:
        error = response.partial_error
        data = response.partial_data
        statistics = response.statistics
        print(f"::warning::Query partially succeeded with error: {error}")
        test_result = "WARN: Query Problems"
    else:
        error = response.partial_error
        data = response.partial_data
        statistics = response.statistics
        print(f"::error::Query failed with error: {error}")
        test_result = "FAIL"

    query_execution_time = statistics['query']['executionTime']
    result_row_count = statistics['query']['datasetStatistics'][0]['tableRowCount']
    result_count = 0

    # Run execution efficiency test if enabled
    if test_execution_efficiency:
        if query_execution_time < EXECUTION_TIME_THRESHOLDS["pass"]:
            test_result = update_test_result(test_result, "PASS")
        elif query_execution_time < EXECUTION_TIME_THRESHOLDS["warn"]:
            test_result = update_test_result(test_result, f"WARN: Took {EXECUTION_TIME_THRESHOLDS['pass']}s+")
        else:
            test_result = update_test_result(test_result, f"FAIL: Took {EXECUTION_TIME_THRESHOLDS['warn']}s+")

    if base_test_type == "alert-back-search":
        # Access the first table, first row, and the second column (count_). If no data found then there were 0 alerts.
        alert_count = data[0].rows[0][1] if data and data[0].rows else 0
        result_count = alert_count
        # Check against configured thresholds
        threshold = ALERT_BACK_SEARCH_THRESHOLDS.get(severity, 0)
        if alert_count <= threshold:
            test_result = update_test_result(test_result, "PASS")
        else:
            test_result = update_test_result(test_result, "FAIL: Too many alerts")
    elif base_test_type == "query-back-search":
        # Calculate number of results
        result_count = result_row_count
        # Check against configured thresholds
        threshold = QUERY_BACK_SEARCH_THRESHOLDS.get(severity, 0)
        if result_count <= threshold:
            test_result = update_test_result(test_result, "PASS")
        else:
            test_result = update_test_result(test_result, "FAIL: Too many results")
    elif base_test_type == "results-diff":
        try:
            # Use Git to retrieve the YAML file from the specified source branch
            source_branch_file_path = f"{source_branch}_{os.path.basename(yaml_file_path)}"
            exit_code = os.system(f"git show {source_branch}:{yaml_file_path} > {source_branch_file_path}")
        
            if exit_code != 0:
                raise FileNotFoundError(f"File {yaml_file_path} does not exist in the '{source_branch}' branch.")
        
            # Load the YAML data from the source branch
            if os.path.exists(source_branch_file_path) and os.path.getsize(source_branch_file_path) > 0:
                with open(source_branch_file_path, "r", encoding="utf-8") as source_file:
                    source_yaml_data = yaml.safe_load(source_file)
            else:
                raise FileNotFoundError(f"Failed to retrieve valid data for {yaml_file_path} from the '{source_branch}' branch.")
        
            # Extract the query from the source branch YAML
            source_query = source_yaml_data.get("query", None)
            if source_query is None:
                raise KeyError("Error: 'query' not found in the YAML file on the source branch.")

        except FileNotFoundError as e:
            print(f"::warning::{e}")
            print("::info::Switching to query-back-search test.")
            base_test_type = "query-back-search"
            result_count = result_row_count

            # Test is pretty loose because it is only for new ARs
            threshold = QUERY_BACK_SEARCH_THRESHOLDS.get(severity, 0)
            if result_count <= threshold:
                test_result = update_test_result(test_result, "PASS")
            else:
                test_result = update_test_result(test_result, "FAIL: Too many results")

        except KeyError as e:
            print(f"::error::{e}")
            test_result = "FAIL: Missing query in source branch YAML"
        except Exception as e:
            print(f"::error::An unexpected error occurred: {e}")
            test_result = "FAIL: Unable to fetch source branch query"

        # Run the query for the source branch version if available
        if 'source_query' in locals() and source_query:
            source_response = client.query_workspace(
                workspace_id=logs_workspace_id,
                query=source_query,
                timespan=time_delta,
                include_statistics=True
            )
            source_result_row_count = source_response.statistics["query"]["datasetStatistics"][0]["tableRowCount"]
    
            # Calculate the difference between our results and the source branch's results
            results_diff = result_row_count - source_result_row_count
            result_count = f"{source_result_row_count}:{result_row_count}"
    
            # Determine the test result based on the difference. Fail if the new query has over RESULTS_DIFF_MULTIPLIER times as many results
            if results_diff <= 0:
                test_result = update_test_result(test_result, "PASS")
            elif source_result_row_count * RESULTS_DIFF_MULTIPLIER < result_row_count:
                test_result = update_test_result(test_result, f"FAIL: Over {RESULTS_DIFF_MULTIPLIER}X results")
            else:
                test_result = update_test_result(test_result, f"WARN: New KQL has {results_diff} more results")
    else:
        test_result = update_test_result(test_result, "unknown")

    # Prepare the results to be written to a YAML file
    results = {
        "rule_name": rule_name,
        "test_type": test_type,
        "test_result": test_result,
        "query": f"{query}",
        "severity": severity,
        "query_time": query_time,
        "query_hash": statistics['query']['queryHash'],
        "query_execution_time": query_execution_time,
        "result_count": result_count
    }

    if include_data:
        results["data"] = []
        if data: 
            # Limit processing to the specified number of rows
            for table in data:
                truncated_rows = table.rows[:include_data]
                formatted_data = []

                # Process each row directly without pandas
                for row in truncated_rows:
                    record = {col: val for col, val in zip(table.columns, row)}

                    # Perform any additional sanitization if needed
                    cleaned_record = {
                        col: (None if pd.isna(val) else str(val) if isinstance(val, (dict, list)) else val)
                        for col, val in record.items()
                    }
                    formatted_data.append(cleaned_record)

                # Convert timestamps and append to results
                results["data"].append(convert_timestamps(formatted_data))

    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)  # Make if doesn't exist
    try:
        with open(output_file_path, "r") as file:
            existing_data = yaml.safe_load(file) or []
    except FileNotFoundError:
        existing_data = []

    existing_data.append(results)

    with open(output_file_path, "w") as file:
        yaml.dump(existing_data, file, default_flow_style=False, sort_keys=False)

    print("Test results successfully appended to test_results/summary.yml")

except HttpResponseError as err:
    print("::error::A fatal error occurred while querying logs")
    print(f"Error Code: {err.error.code}")
    print(f"Error Message: {err.message}")
    print(err)

    test_result = "FAIL: Query Failed"

    error_results = {
        "rule_name": rule_name,
        "test_type": test_type,
        "test_result": test_result,
        "query": f"{query}",
        "severity": severity,
        "query_time": query_time,
        "statistics": {
            "queryHash": "unknown",
            "query_execution_time": "unknown",
            "result_row_count": 0
        },
        "error": {
            "code": err.error.code,
            "message": err.message
        }
    }

    if include_data:
        error_results["data"] = []

    # Read the existing YAML file if it exists
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    try:
        with open(output_file_path, "r") as file:
            existing_data = yaml.safe_load(file)
            if existing_data is None:
                existing_data = []
    except FileNotFoundError:
        existing_data = []

    existing_data.append(error_results)

    with open(output_file_path, "w") as file:
        yaml.dump(existing_data, file, Dumper=CustomDumper, default_flow_style=False, sort_keys=False)

print("Processing complete.")
