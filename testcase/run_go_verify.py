import subprocess
import os
import sys

work_dir = r"g:\workspaces\git\corssmool\crossmool"
go_verify_exe = os.path.join(work_dir, "testcase", ".go_interop_temp", "verify_java_data", "verify_java_data.exe")
input_file = os.path.join(work_dir, "testcase", "java_go_test_data.json")
log_file = os.path.join(work_dir, "testcase", "go_verify.log")

with open(log_file, "w", encoding="utf-8") as log:
    log.write("=== Go Verify Java-Generated SM Data ===\n")
    log.write(f"Input file: {input_file}\n")
    log.write(f"Executable: {go_verify_exe}\n\n")
    
    cmd = [go_verify_exe, input_file]
    log.write("CMD: " + " ".join(cmd) + "\n\n")
    log.flush()
    
    result = subprocess.run(cmd, cwd=work_dir, capture_output=True, text=True, timeout=60)
    
    log.write("STDOUT:\n" + result.stdout + "\n")
    log.write("STDERR:\n" + result.stderr + "\n")
    log.write("Return code: " + str(result.returncode) + "\n")
    
    if result.returncode == 0:
        print("SUCCESS - All Go verification tests passed!")
    else:
        print("FAILED - See log for details")
    
    print("Log saved to:", log_file)

sys.exit(result.returncode)