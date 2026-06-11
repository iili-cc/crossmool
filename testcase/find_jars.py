import os
import glob

home = os.path.expanduser("~")
m2 = os.path.join(home, ".m2", "repository")

# Find bcprov jar
for f in glob.glob(os.path.join(m2, "org", "bouncycastle", "**", "*.jar"), recursive=True):
    print(f"BCPROV: {f}")

# Find lombok jar
for f in glob.glob(os.path.join(m2, "org", "projectlombok", "**", "*.jar"), recursive=True):
    print(f"LOMBOK: {f}")

# Find logback jar
for f in glob.glob(os.path.join(m2, "ch", "qos", "logback", "**", "*.jar"), recursive=True):
    print(f"LOGBACK: {f}")

# Find slf4j jar
for f in glob.glob(os.path.join(m2, "org", "slf4j", "**", "*.jar"), recursive=True):
    print(f"SLF4J: {f}")

# Check target directory
target_dir = r"g:\workspaces\git\corssmool\crossmool\java\crossmool\target"
if os.path.exists(target_dir):
    for f in glob.glob(os.path.join(target_dir, "**", "*.jar"), recursive=True):
        print(f"TARGET: {f}")
    classes_dir = os.path.join(target_dir, "classes")
    if os.path.exists(classes_dir):
        print(f"CLASSES: {classes_dir}")