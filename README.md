# kql-tester
KQL Quality Assurance tests... because no one likes false positives.

Script assumes rule format is like https://github.com/Azure/Azure-Sentinel.

## Test Types
**query-back-search**: Tests if a query returns too many results over a given time period. Uses severity-based thresholds to determine pass/fail. Can be customized to dynamically search over non-severity fields as well.
**results-diff**: Compares query results between current branch and source branch. Fails if current query returns significantly more results. If the rule does not exist on the source branch (identified by file name) then it is assumed to be new and runs query-back-search.
**execution-efficiency**: Tests query performance against execution time thresholds. Will warn if the query run-time is getting too long. Can be used standalone or combined with other test types using the `--ExecutionEfficiency` flag.
**alert-back-search**: Tests if a detection rule has generated too many alerts. Helpful reviewing analytic rules in mass on a regular basis.
## Installation
```bash
git clone https://github.com/BlakeHensleyy/kql-tester.git
cd kql-tester
pip install -r requirements.txt
```

### Basic Usage Examples
```bash
# Test query efficiency using time from YAML file
python kql-tester.py -d rule.yaml -tT query-back-search -tF

# Test with custom time period and execution efficiency
python kql-tester.py -d rule.yaml -tT query-back-search -t 7d -eE

# Compare against a different branch
python kql-tester.py -d rule.yaml -tT results-diff -tF -sB develop

# Test alert generation with data included
python kql-tester.py -d rule.yaml -tT alert-back-search -t 30d -iD 5
```

## Output Format

Test results are saved to a YAML file (default: `test_results/results.yml`) with the following structure:

```yaml
- rule_name: "Suspicious Registry Modification"
  test_type: "query-back-search"
  test_status: "PASS"  # or "WARN" or "FAIL"
  test_details: "Too many results (25 > 15)"  # Only present for non-PASS results
  query: "SecurityEvent | where EventID == 4688..."
  severity: "Medium"
  query_time: "days=7, hours=0, minutes=0"
  query_hash: "abc123..."
  query_execution_time: 2.34
  result_count: 15
  test_run_time: "2025-01-15T10:30:45.123456+00:00"
  data: [...]  # Only if --IncludeData is used
```

**Field Descriptions:**
- `test_status`: PASS, WARN, or FAIL
- `test_details`: Only present when status is not PASS, contains failure/warning reason
- `result_count`: Number of results returned by query (or "old:new" format for results-diff)
- `query_execution_time`: Time in seconds the query took to execute
- `test_run_time`: UTC timestamp when the test was executed
- `data`: Sample query results (if --IncludeData flag used)

## Environment Variables

**Required:**
- `LOGS_WORKSPACE_ID`: Your Log Analytics Workspace ID

**Optional (for Service Principal auth):**
- `AZURE_CLIENT_ID`: Application (client) ID
- `AZURE_CLIENT_SECRET`: Client secret
- `AZURE_TENANT_ID`: Directory (tenant) ID

## Setup the Log Analytics API
1. Register a new Azure Application in "App Registrations". 

2. Create a new secret in the new application.

3. Give the Application "Log Analytics Reader" role in the target Log Analytics Workspace IAM settings.

4. Set the workspace ID environment variable:
```bash
# For Bash/Git Bash
export LOGS_WORKSPACE_ID="your-workspace-id-here"

# For PowerShell  
$env:LOGS_WORKSPACE_ID="your-workspace-id-here"
```

## Authentication Setup

`kql-tester` uses Azure's `DefaultAzureCredential`, which automatically tries multiple authentication methods in order until one succeeds. This provides seamless authentication across different environments without additional configuration.

**Authentication methods tried automatically (in order):**
1. **Environment variables** (Service Principal)
2. **Managed Identity** (Azure-hosted environments)  
3. **Azure CLI** (Local development)
4. **Azure PowerShell** 
5. **Interactive Browser** (Fallback)

### For Local Development (Recommended)
```bash
# Login with Azure CLI (easiest for local development)
az login

# Set workspace ID
export LOGS_WORKSPACE_ID="your-workspace-id"
```

### For CI/CD Pipelines
```bash
# Set environment variables for Service Principal authentication
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret" 
export AZURE_TENANT_ID="your-tenant-id"
export LOGS_WORKSPACE_ID="your-workspace-id"
```

### For Azure-hosted Environments
```bash
# Only need workspace ID - Managed Identity handles authentication automatically
export LOGS_WORKSPACE_ID="your-workspace-id"
```

### Setup Steps:

1. **Create Azure App Registration:**
   ```bash
   az ad app create --display-name "kql-tester"
   ```

2. **Create Service Principal (for CI/CD):**
   ```bash
   az ad sp create-for-rbac --name "kql-tester" --role "Log Analytics Reader" --scopes "/subscriptions/{subscription-id}/resourceGroups/{rg-name}/providers/Microsoft.OperationalInsights/workspaces/{workspace-name}"
   ```

3. **Find your workspace ID:**
   ```bash
   az monitor log-analytics workspace show --resource-group {rg-name} --workspace-name {workspace-name} --query customerId -o tsv
   ```

## GitHub Actions Example
This is an example of how `kql-tester` could be used in production. Included in the actions is every query-based test that `kql-tester` is capable of.

```yaml
name: KQL Tests
on: [pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
      with:
        fetch-depth: 0  # Fetch full history for diff test.
    
    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install kql-tester
      run: |
        pip install -r requirements.txt
    
    - name: Get changed YAML files
      id: changed-files
      run: |
        git diff --name-only ${{ github.event.pull_request.base.sha }} ${{ github.sha }} | grep '\.ya\?ml$' > changed_files.txt || true
        
        if [ -s changed_files.txt ]; then
          echo "has_changes=true" >> $GITHUB_OUTPUT
        else
          echo "has_changes=false" >> $GITHUB_OUTPUT
        fi
    
    - name: Run KQL Tests on changed files
      if: steps.changed-files.outputs.has_changes == 'true'
      env:
        AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
        AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
        AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
        LOGS_WORKSPACE_ID: ${{ secrets.LOGS_WORKSPACE_ID }}
      run: | 
        while IFS= read -r file; do
          if [ -f "$file" ]; then
            echo "Testing file: $file"
            python kql-tester.py -d "$file" -tT query-back-search -eE -tF  # Does the KQL compile and run? Is it efficient?
            python kql-tester.py -d "$file" -tT results-diff -tF          # Is the changed rule worse than before?
          fi
        done < changed_files.txt
    
    ############# Steps after this point are optional and are for easy production usage ###############
    # First checks that there were results in case of disabled/undeployed rules which are not kql tested.
    - name: Format and Display Test Results
      run: |       
        if [ ! -f test_results/results.yml ]; then
          echo "No results.yml found. Skipping test results formatting."
        else
          echo "Formatting test results... This process will fail if a test FAILed."
          cd .github
          python format-test-results.py
          cat test-results.md >> $GITHUB_STEP_SUMMARY
        fi

    - name: Store Test Results as Artifacts
      uses: actions/upload-artifact@v4
      with:
        name: test_results
        path: test_results/results.yml
      continue-on-error: true
```