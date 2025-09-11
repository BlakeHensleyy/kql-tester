import yaml
import os
import sys

# Configuration
WRITE_TO_FILE = True
RESULTS_FILE = os.environ.get('RESULTS_FILE', os.path.join('test_results', 'results.yml'))
OUTPUT_FILE = "test-results.md"

def format_test_results():
    """Format and display test results from results file."""

    # Validate file exists
    if not os.path.exists(RESULTS_FILE):
        error_msg = f"❌ Summary file not found: {RESULTS_FILE}"
        print(error_msg)
        if WRITE_TO_FILE:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(f"# Test Results\n\n{error_msg}\n")
        sys.exit(1)

    # Load test data
    with open(RESULTS_FILE, 'r') as f:
        results = yaml.safe_load(f)

    output_lines = []
    
    # Count results by status
    pass_count = len([r for r in results if r.get('test_status', '') == 'PASS'])
    warn_count = len([r for r in results if r.get('test_status', '') == 'WARN'])
    fail_count = len([r for r in results if r.get('test_status', '') == 'FAIL'])
    total_count = len(results)

    output_lines.append("## Test Results Summary")
    output_lines.append(f"✅ **PASSED:** {pass_count}")
    output_lines.append(f"⚠️  **WARNINGS:** {warn_count}")  
    output_lines.append(f"❌ **FAILED:** {fail_count}")
    output_lines.append("")
    output_lines.append("📋 Check artifacts for detailed analysis and details in test_results/results.yml")
    output_lines.append("")

    output_lines.append("## Test Details")
    output_lines.append(f"{'Rule':<75} | {'Result':<8} | {'Type':<15} | {'Severity':<8} | {'Count':<8}")
    output_lines.append(f"{'-'*75} | {'-'*8} | {'-'*15} | {'-'*8} | {'-'*8}")

    for test in results:
        rule = test.get('rule_name', 'Unknown')[:74]
        result = test.get('test_status', 'N/A')
        test_type = test.get('test_type', 'N/A')
        severity = test.get('severity', 'N/A')
        count = test.get('result_count', 0)

        # Add status emoji
        if result == 'FAIL':
            result_display = f"❌ {result}"
        elif result == 'WARN':
            result_display = f"⚠️ {result}"
        else:
            result_display = f"✅ {result}"

        output_lines.append(f"{rule:<75} | {result_display:<8} | {test_type:<15} | {severity:<8} | {count:<8}")

    output_lines.append("")
    
    # Final status
    if total_count == 0:
        status_msg = "🔵 No tests to run"
        exit_code = 0
    elif fail_count > 0:
        status_msg = "🔴 Build FAILED - Tests have failures"
        exit_code = 1
    else:
        status_msg = "🟢 Build PASSED - All tests successful"
        exit_code = 0
    
    output_lines.append(status_msg)

    # Write to file if enabled
    if WRITE_TO_FILE:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write("# KQL Test Results\n\n")
            for line in output_lines:
                f.write(line + "\n")
        print(f"\n📝 Results written to: {OUTPUT_FILE}")
    else:
        for line in output_lines:
            print(line)

    sys.exit(exit_code)


if __name__ == "__main__":
    format_test_results()
