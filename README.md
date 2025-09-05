# kql-tester
KQL Quality Assurance tests... because no one likes false positives.

## Test Types
- Query performance testing
- Result count validation
- Alert generation monitoring
- Branch comparison testing

## Installation
```bash
git clone https://github.com/BlakeHensleyy/KQLQueryTests.git
cd KQLQueryTests
pip install -r requirements.txt
```

## Usage
```bash
python kql-tester.py -d rule.yml -tT query-back-search -tF
```

## Setup the log analytics API
1. Register a new Azure Application in "App Registrations". 

2. Create a new secret in the new application.

3. Give the Application "Log Analytics Reader" role in the target Log Analytics Workspace IAM settings.

4. Create environment variables:
AZURE_CREDENTIALS
```
{
  "clientId": "YOUR_CLIENT_ID",
  "clientSecret": "YOUR_CLIENT_SECRET",
  "subscriptionId": "YOUR_SUBSCRIPTION_ID",
  "tenantId": "YOUR_TENANT_ID"
}
```
LOGS_WORKSPACE_ID
```
40861252-b4f7-49ac-b361-b4d9015eb318
```
example^

## Authentication Setup

`kql-tester` supports multiple authentication methods. Choose the one that works best for your environment:

### Option 1: Azure CLI (Recommended for local development)
```bash
# Login with Azure CLI
az login

# Set workspace ID
export LOGS_WORKSPACE_ID="your-workspace-id"
```

### Option 2: Service Principal (Recommended for CI/CD)
```bash
# Set environment variables
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret" 
export AZURE_TENANT_ID="your-tenant-id"
export LOGS_WORKSPACE_ID="your-workspace-id"
```

### Option 3: Managed Identity (For Azure-hosted environments)
```bash
# Only need workspace ID - authentication handled automatically
export LOGS_WORKSPACE_ID="your-workspace-id"
```

### Setup Steps:

1. **Create Azure App Registration:**
   ```bash
   az ad app create --display-name "kql-tester"
   ```

2. **Create Service Principal (if using Option 2):**
   ```bash
   az ad sp create-for-rbac --name "kql-tester" --role "Log Analytics Reader" --scopes "/subscriptions/{subscription-id}/resourceGroups/{rg-name}/providers/Microsoft.OperationalInsights/workspaces/{workspace-name}"
   ```

3. **Find your workspace ID:**
   ```bash
   az monitor log-analytics workspace show --resource-group {rg-name} --workspace-name {workspace-name} --query customerId -o tsv
   ```

## GitHub Actions Example

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
            python kql-tester.py -d "$file" -tT query-back-search -tF
          fi
        done < changed_files.txt
```

## Local Development

For local development, the easiest approach is using Azure CLI:

```bash
# One-time setup
git clone https://github.com/BlakeHensleyy/KQLQueryTests.git
cd KQLQueryTests
pip install -r requirements.txt
az login
export LOGS_WORKSPACE_ID="your-workspace-id"

# Run tests
python kql-tester.py -d rule.yml -tT query-back-search -tF
```
export LOGS_WORKSPACE_ID="your-workspace-id"
