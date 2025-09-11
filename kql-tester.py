import os
import sys
import argparse
import pandas as pd
import re
import yaml
from datetime import timedelta, datetime, timezone
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
    "Informational": 30,
    "Low": 10,
    "Medium": 5,
    "High": 1
}

# The main flaw with query backtesting in KQL is that it is evaluating based on the number of returned rows. 
# IE there could be 10 resulting rows per triggered alert. That doesn't mean there are 10 FPs, but likely 1.
# TODO: Calculate the estimated alert number using queryPeriod and queryFrequency to fix this.
# This is why the default thresholds are higher than alert threshold
QUERY_BACK_SEARCH_THRESHOLDS = { # Set all to the same number if you don't want it dynamic.
    "Informational": 100,
    "Low": 50,
    "Medium": 15,
    "High": 5
}

# Configuration: Results diff thresholds by severity
RESULTS_DIFF_THRESHOLDS = {
    "Informational": 5.0,  # Allow up to 5x increase
    "Low": 3.0,           # Allow up to 3x increase
    "Medium": 2.0,        # Allow up to 2x increase
    "High": 1.5          # Only allow 50% increase
}

test_descriptions = """
Available Test Types:
  query-back-search        - Tests if a query returns too many results over a given time period.
                            Uses severity-based thresholds to determine pass/fail.
                            
  alert-back-search        - Tests if a detection rule has generated too many alerts.
                            Queries AlertInfo table to count alerts by rule name.
                            
  results-diff            - Compares query results between current branch and source branch.
                            Fails if current query returns significantly more results.
                            
  execution-efficiency    - Tests query performance against execution time thresholds.
                            Can be used standalone or with any other test type using --ExecutionEfficiency flag.
"""

parser = argparse.ArgumentParser(
    description="KQL Query Testing Tool for Microsoft Sentinel",
    epilog=test_descriptions,
    formatter_class=argparse.RawDescriptionHelpFormatter
)
parser.add_argument("-d", "--YamlPath", dest="YamlPath", required=True, help="YAML file containing the query field.")
parser.add_argument("-tF", "--TimeFromFile", action=argparse.BooleanOptionalAction, help="To use the query time in the YAML file.")
parser.add_argument("-t", "--QueryTime", dest="QueryTime", help="Provide the searchback time if TimeFromFile set to false. Provide in this format: 1d, 2h, 5m")
parser.add_argument("-tT", "--TestType", dest="TestType", required=True, help="Test type: query-back-search, alert-back-search, results-diff, execution-efficiency.")
parser.add_argument("-eE", "--ExecutionEfficiency", action="store_true", help="Enable execution efficiency testing alongside the main test type.")
parser.add_argument("-iD", "--IncludeData", dest="IncludeData", nargs="?", const=10, type=int, help="Include data in the output YAML file. Optionally specify the maximum number of rows to include (default is 10).")
parser.add_argument("-sB", "--SourceBranch", dest="SourceBranch", default="main", help="Source branch for results-diff test type. Default is 'main'.")
parser.add_argument("-o", "--OutputPath", dest="OutputPath", default="test_results/results.yml", help="Path to the output YAML file.")

args = parser.parse_args()

yaml_file_path = args.YamlPath
time_from_file = args.TimeFromFile
query_time = args.QueryTime
test_type = args.TestType
execution_efficiency = args.ExecutionEfficiency
include_data = args.IncludeData
source_branch = args.SourceBranch
output_file_path = args.OutputPath
test_status = None
test_details = None

# Validate SourceBranch is only used with results-diff
if test_type != "results-diff" and source_branch != "main":
    print("::warning::SourceBranch argument is only applicable for results-diff test type. Ignoring.")

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

# Initialize the Azure Monitor Logs client.
# Has falback auth method order of: env variables > Managed Identity > az CLI > Azure PWSH > Browser.
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
    rule_kind = yaml_data.get('kind', 'Scheduled')
    if rule_kind != "NRT":
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

# If the test is alert-back-search, replace the query to find the number of alerts in the allotted time.
if test_type == "alert-back-search":
    if not include_data:
        include_data = True
        print("--IncludeData option set to true because alert-back-search is used.")
    query = f'AlertInfo | where Title == "{rule_name}" | summarize count() by Title'

# Make the request and format the results.
try:
    kwargs = eval(f"dict({query_time})")
    time_delta = timedelta(**kwargs)
    # Note: The timespan in the API request overrides any timeGenerated values in the KQL.
    response = client.query_workspace(
        workspace_id=logs_workspace_id,
        query=query,
        timespan=time_delta,
        include_statistics=True
    )

    if response.status == LogsQueryStatus.SUCCESS:
        data = response.tables
        statistics = response.statistics
        test_status = "PASS"
        test_details = None
    elif response.status == LogsQueryStatus.PARTIAL:
        error = response.partial_error
        data = response.partial_data
        statistics = response.statistics
        print(f"::warning::Query partially succeeded with error: {error}")
        test_status = "WARN"
        test_details = "Query Problems"
    else:
        error = response.partial_error
        data = response.partial_data
        statistics = response.statistics
        print(f"::error::Query failed with error: {error}")
        test_status = "FAIL"
        test_details = "Query execution failed"

    query_execution_time = statistics['query']['executionTime']
    result_row_count = statistics['query']['datasetStatistics'][0]['tableRowCount']
    result_count = 0

    if test_type == "alert-back-search":
        alert_count = data[0].rows[0][1] if data and data[0].rows else 0
        result_count = alert_count
        threshold = ALERT_BACK_SEARCH_THRESHOLDS.get(severity, 0)
        if alert_count <= threshold:
            test_status = "PASS"
            test_details = None
        else:
            test_status = "FAIL"
            test_details = f"Too many alerts ({alert_count} > {threshold})"
    elif test_type == "query-back-search":
        result_count = result_row_count
        threshold = QUERY_BACK_SEARCH_THRESHOLDS.get(severity, 0)
        if result_count <= threshold:
            test_status = "PASS"
            test_details = None
        else:
            test_status = "FAIL"
            test_details = f"Too many results ({result_count} > {threshold})"
    elif test_type == "execution-efficiency":
        result_count = result_row_count
        if query_execution_time < EXECUTION_TIME_THRESHOLDS["pass"]:
            test_status = "PASS"
            test_details = None
        elif query_execution_time < EXECUTION_TIME_THRESHOLDS["warn"]:
            test_status = "WARN"
            test_details = f"Took {query_execution_time:.1f}s (>{EXECUTION_TIME_THRESHOLDS['pass']}s)"
        else:
            test_status = "FAIL"
            test_details = f"Took {query_execution_time:.1f}s (>{EXECUTION_TIME_THRESHOLDS['warn']}s)"
    elif test_type == "results-diff":
        try:
            # Use Git to retrieve the YAML file from the specified source branch
            source_branch_file_path = f"{source_branch}_{os.path.basename(yaml_file_path)}"
            exit_code = os.system(f"git show {source_branch}:{yaml_file_path} > {source_branch_file_path}")
            if exit_code != 0:
                raise FileNotFoundError(f"File {yaml_file_path} does not exist in the '{source_branch}' branch.")
            if os.path.exists(source_branch_file_path) and os.path.getsize(source_branch_file_path) > 0:
                with open(source_branch_file_path, "r", encoding="utf-8") as source_file:
                    source_yaml_data = yaml.safe_load(source_file)
            else:
                raise FileNotFoundError(f"Failed to retrieve valid data for {yaml_file_path} from the '{source_branch}' branch.")
            source_query = source_yaml_data.get("query", None)
            if source_query is None:
                raise KeyError("Error: 'query' not found in the YAML file on the source branch.")
        except FileNotFoundError as e:
            print(f"::warning::{e}")
            print("::info::Switching to query-back-search test.")
            test_type = "query-back-search"
            result_count = result_row_count
            threshold = QUERY_BACK_SEARCH_THRESHOLDS.get(severity, 0)
            if result_count <= threshold:
                test_status = "PASS"
                test_details = None
            else:
                test_status = "FAIL"
                test_details = f"Too many results ({result_count} > {threshold})"
        except KeyError as e:
            print(f"::error::{e}")
            test_status = "FAIL"
            test_details = "Missing query in source branch YAML"
        except Exception as e:
            print(f"::error::An unexpected error occurred: {e}")
            test_status = "FAIL"
            test_details = "Unable to fetch source branch query"
    
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
            
            # Use 1 instead of 0 for ratio calculation if source was zero
            calc_source_count = 1 if source_result_row_count == 0 else source_result_row_count
            results_ratio = result_row_count / calc_source_count
            threshold = RESULTS_DIFF_THRESHOLDS.get(severity, 2.0)
            if results_diff <= 0:
                test_status = "PASS"
                test_details = None
            elif source_result_row_count == 0:
                if result_row_count > QUERY_BACK_SEARCH_THRESHOLDS.get(severity, 0):
                    test_status = "FAIL"
                    test_details = f"Query now returns {result_row_count} results (was 0)"
                else:
                    test_status = "WARN"
                    test_details = f"Query now returns {result_row_count} results (was 0)"
            elif results_ratio > threshold:
                test_status = "FAIL"
                test_details = f"{results_ratio:.1f}X results (>{threshold}X for {severity})"
            else:
                test_status = "WARN"
                test_details = f"New KQL has {results_diff} more results ({results_ratio:.1f}X)"
        else:
            test_status = "FAIL"
            test_details = "Unknown test type"

    # Prepare the results to be written to a YAML file
    results = {
        "rule_name": rule_name,
        "test_type": test_type,
        "test_status": test_status,
        **({"test_details": test_details} if test_details is not None else {}),
        "query": query,
        "severity": severity,
        "query_time": query_time,
        "query_hash": statistics['query']['queryHash'],
        "query_execution_time": query_execution_time,
        "result_count": result_count,
        "test_run_time": datetime.now(timezone.utc).isoformat()
    }

    if include_data:
        results["data"] = []
        if data: 
            # Limit processing to the specified number of rows
            for table in data:
                truncated_rows = table.rows[:include_data]
                formatted_data = []
                for row in truncated_rows:
                    record = {col: val for col, val in zip(table.columns, row)}

                    # Perform any sanitization if needed
                    cleaned_record = {
                        col: (None if pd.isna(val) else str(val) if isinstance(val, (dict, list)) else val)
                        for col, val in record.items()
                    }
                    formatted_data.append(cleaned_record)

                # Convert timestamps and append to results
                results["data"].append(convert_timestamps(formatted_data))

    # Read existing data and append base test result
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)  # Make if doesn't exist
    try:
        with open(output_file_path, "r") as file:
            existing_data = yaml.safe_load(file) or []
    except FileNotFoundError:
        existing_data = []

    existing_data.append(results)

    # Add execution efficiency result if enabled
    if execution_efficiency:
        if query_execution_time < EXECUTION_TIME_THRESHOLDS["pass"]:
            efficiency_status = "PASS"
            efficiency_details = None
        elif query_execution_time < EXECUTION_TIME_THRESHOLDS["warn"]:
            efficiency_status = "WARN"
            efficiency_details = f"Took {query_execution_time:.1f}s (>{EXECUTION_TIME_THRESHOLDS['pass']}s)"
        else:
            efficiency_status = "FAIL"
            efficiency_details = f"Took {query_execution_time:.1f}s (>{EXECUTION_TIME_THRESHOLDS['warn']}s)"
        efficiency_test_result = {
            "rule_name": rule_name,
            "test_type": "execution-efficiency",
            "test_status": efficiency_status,
            **({"test_details": efficiency_details} if efficiency_details is not None else {}),
            "query": query,
            "severity": severity,
            "query_time": query_time,
            "query_hash": statistics['query']['queryHash'],
            "query_execution_time": query_execution_time,
            "result_count": result_row_count,
            "test_run_time": datetime.now(timezone.utc).isoformat()
        }
        existing_data.append(efficiency_test_result)

    with open(output_file_path, "w") as file:
        yaml.dump(existing_data, file, default_flow_style=False, sort_keys=False)

    print(f"Test results successfully appended to {output_file_path}")

except HttpResponseError as err:
    print("::error::A fatal error occurred while querying logs")
    print(f"Error Code: {err.error.code}")
    print(f"Error Message: {err.message}")
    print(err)

    test_status = "FAIL"
    test_details = "Query Failed"
    error_results = {
        "rule_name": rule_name,
        "test_type": test_type,
        "test_status": test_status,
        **({"test_details": test_details} if test_details is not None else {}),
        "query": query,
        "severity": severity,
        "query_time": query_time,
        "statistics": {
            "query_hash": "unknown",
            "query_execution_time": "unknown",
            "result_row_count": 0
        },
        "error": {
            "code": err.error.code,
            "message": err.message
        },
        "test_run_time": datetime.now(timezone.utc).isoformat()
    }

    if include_data:
        error_results["data"] = []

    # Read the existing YAML file if it exists. This is for looped workflows.
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
