# kql-tester
KQL Quality Assurance tests... because no one likes false positives.

Script assumes rule format is like https://github.com/Azure/Azure-Sentinel.
## Test Types
**query-back-search**: Tests if a query returns too many results over a given time period. Uses severity-based thresholds to determine pass/fail. Can be customized to dynamically search over non-severity fields as well.
**results-diff**: Compares query results between current branch and source branch. Fails if current query returns significantly more results. If the rule does not exist on the source branch (identified by file name) then it is assumed to be new and runs query-back-search.
**execution-efficiency**: Can be added as suffix to any test (e.g., query-back-search-execution-efficiency). Tests query performance against execution time thresholds. Will warn if the query run-time is getting too long.
**alert-back-search**: Tests if a detection rule has generated too many alerts. Helpful reviewing analytic rules in mass on a regular basis.
## Installation
```bash
git clone https://github.com/BlakeHensleyy/kql-tester.git
cd kql-tester
pip install -r requirements.txt
```

### Basic Usage
```bash
python kql-tester.py -d rule.yaml -tT query-back-search -tF
```

## Setup the log analytics API
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
            python kql-tester.py -d "$file" -tT query-back-search -eE -tF # Does the KQL compile and run? Is the run efficient?
            python kql-tester.py -d "$file" -tT results-diff -tF # Is the changed rule worse than before?
          fi
        done < changed_files.txt
    
    ############# Steps after this point are optional and are for easy production usage ###############
    # First checks that there were results in case of disabled/undeployed rules which are not kql tested.
    - name: Pretty Display KQL Testing Results.
      run: |       
        if [ ! -f test_results/results.yml ]; then
          echo "No results.yml found. Skipping test results formatting."
        else
          echo "Formatting test results... This process will fail if a test FAILed."
          cd .github
          python format-test-results.py
          cat test-results.md >> $GITHUB_STEP_SUMMARY
        fi

    # Store test_results/results.yml as a job artifact (after formatting is done)
    - name: Store Artifacts
      uses: actions/upload-artifact@v4
      with:
        name: test_results
        path: |
          test_results/results.yml
          .github/test-results.md
      continue-on-error: true
```