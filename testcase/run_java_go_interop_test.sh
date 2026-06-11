#!/bin/bash
# Java-Go SM2/SM3/SM4 Interoperability Test Runner
# 一键运行所有互通性测试

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(dirname "$SCRIPT_DIR")"
JAVA_DIR="$WORKSPACE/java/crossmool"
GO_DIR="$WORKSPACE/golang/crossmool"
VERIFY_DIR="$WORKSPACE/golang/verify"
TESTCASE_DIR="$SCRIPT_DIR"

echo "============================================================"
echo "Java-Go SM2/SM3/SM4 Interoperability Test Runner"
echo "============================================================"
echo ""

# Step 1: Compile Java project
echo "[Step 1/4] Compiling Java project..."
cd "$JAVA_DIR"
mvn clean compile -q
if [ $? -eq 0 ]; then
    echo "  ✅ Java compilation successful"
else
    echo "  ❌ Java compilation failed"
    exit 1
fi

# Step 2: Generate test data with Java
echo ""
echo "[Step 2/4] Generating test data with Java..."
cd "$JAVA_DIR"
CP="target/classes;$(cat cp.txt)"
javac -cp "$CP" -d target/classes ../../testcase/JavaGoInteropTest.java 2>&1 | grep -v "注:" || true
java -cp "$CP" JavaGoInteropTest > "$TESTCASE_DIR/java_go_test_output.txt" 2>&1
if [ $? -eq 0 ]; then
    echo "  ✅ Java test data generation successful"
    echo "  Output saved to: $TESTCASE_DIR/java_go_test_output.txt"
else
    echo "  ❌ Java test data generation failed"
    exit 1
fi

# Step 3: Run Go unit tests
echo ""
echo "[Step 3/4] Running Go unit tests..."
cd "$GO_DIR"
go mod tidy 2>&1 | grep -v "^go: downloading" || true
go test -v -run "SM4|SM2|SM3" > "$TESTCASE_DIR/go_unit_test_output.txt" 2>&1
if [ $? -eq 0 ]; then
    echo "  ✅ Go unit tests passed"
    echo "  Output saved to: $TESTCASE_DIR/go_unit_test_output.txt"
else
    echo "  ❌ Go unit tests failed"
    cat "$TESTCASE_DIR/go_unit_test_output.txt"
    exit 1
fi

# Step 4: Run Go verification
echo ""
echo "[Step 4/4] Running Go verification of Java data..."
cd "$VERIFY_DIR"
go mod tidy 2>&1 | grep -v "^go: downloading" || true
go run verify_java_interop.go > "$TESTCASE_DIR/go_verify_output.txt" 2>&1
if [ $? -eq 0 ]; then
    echo "  ✅ Go verification successful"
    echo "  Output saved to: $TESTCASE_DIR/go_verify_output.txt"
else
    echo "  ❌ Go verification failed"
    cat "$TESTCASE_DIR/go_verify_output.txt"
    exit 1
fi

# Summary
echo ""
echo "============================================================"
echo "Test Summary"
echo "============================================================"
echo ""
echo "✅ All tests passed successfully!"
echo ""
echo "Test outputs:"
echo "  - Java test data:  $TESTCASE_DIR/java_go_test_output.txt"
echo "  - Go unit tests:   $TESTCASE_DIR/go_unit_test_output.txt"
echo "  - Go verification: $TESTCASE_DIR/go_verify_output.txt"
echo "  - Test report:     $TESTCASE_DIR/Java-Go-interop-test-report.md"
echo ""
echo "============================================================"

# Display verification summary
echo ""
echo "=== Go Verification Summary ==="
grep -A 20 "Summary" "$TESTCASE_DIR/go_verify_output.txt" | head -20

exit 0