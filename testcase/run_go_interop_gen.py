import subprocess
import os
import sys

java_home = r"H:\Programs\Java\jdk-21.0.1+12"
javac = os.path.join(java_home, "bin", "javac.exe")
java_exe = os.path.join(java_home, "bin", "java.exe")

work_dir = r"g:\workspaces\git\corssmool\crossmool"

cp_sep = ";"
cp = cp_sep.join([
    r"java\crossmool\target\classes",
    r"java\crossmool\target\dependency\bcprov-jdk18on-1.82.jar",
    r"java\crossmool\target\dependency\lombok-1.18.42.jar",
    r"java\crossmool\target\dependency\slf4j-api-2.0.17.jar",
    r"java\crossmool\target\dependency\logback-classic-1.5.22.jar",
    r"java\crossmool\target\dependency\logback-core-1.5.22.jar",
])

log_file = os.path.join(work_dir, "testcase", "go_interop_gen.log")

with open(log_file, "w", encoding="utf-8") as log:
    # Step 1: Compile
    log.write("=== Compiling ===\n")
    compile_cmd = [
        javac, "-encoding", "UTF-8",
        "-cp", cp,
        os.path.join("testcase", "GenerateGoInteropData.java")
    ]
    log.write("CMD: " + " ".join(compile_cmd) + "\n")
    log.flush()
    result = subprocess.run(compile_cmd, cwd=work_dir, capture_output=True, text=True)
    log.write("STDOUT: " + result.stdout + "\n")
    log.write("STDERR: " + result.stderr + "\n")
    log.write("Return code: " + str(result.returncode) + "\n")
    log.flush()

    if result.returncode != 0:
        log.write("COMPILE FAILED\n")
        print("COMPILE FAILED - see log")
        sys.exit(1)

    log.write("COMPILE SUCCESS\n\n")

    # Step 2: Run
    log.write("=== Running ===\n")
    run_cp = cp_sep.join(["testcase", cp])
    run_cmd = [
        java_exe, "-cp", run_cp,
        "GenerateGoInteropData",
        os.path.join("testcase", "java_go_test_data.json")
    ]
    log.write("CMD: " + " ".join(run_cmd) + "\n")
    log.flush()
    result = subprocess.run(run_cmd, cwd=work_dir, capture_output=True, text=True, timeout=60)
    log.write("STDOUT: " + result.stdout + "\n")
    log.write("STDERR: " + result.stderr + "\n")
    log.write("Return code: " + str(result.returncode) + "\n")
    log.flush()

    if result.returncode != 0:
        log.write("RUN FAILED\n")
        print("RUN FAILED - see log")
        sys.exit(1)

    # Step 3: Check output file
    output_path = os.path.join(work_dir, "testcase", "java_go_test_data.json")
    if os.path.exists(output_path):
        with open(output_path, "r", encoding="utf-8") as f:
            log.write("\n=== Output JSON ===\n")
            log.write(f.read())
        print("SUCCESS - output file generated")
    else:
        log.write("OUTPUT FILE NOT FOUND\n")
        print("OUTPUT FILE NOT FOUND")

print("Done. Log saved to:", log_file)