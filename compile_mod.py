import os
import subprocess
import zipfile
import shutil

# Relative project directories
project_root = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(project_root, "src", "main", "java")
resources_dir = os.path.join(project_root, "src", "main", "resources")
build_dir = os.path.join(project_root, "build_output")
dest_jar = os.path.join(project_root, "mcchatbridge-1.0.2.jar")

# 1. Clean build directory
if os.path.exists(build_dir):
    shutil.rmtree(build_dir)
os.makedirs(build_dir, exist_ok=True)

# 2. Compile Java classes
# Use system javac (JDK must be installed and added to system PATH)
javac_path = "javac"

# Classpath setup: users should specify their path to Minecraft/NeoForge libraries.
# By default, we search in the local 'lib' directory
lib_dir = os.path.join(project_root, "lib")
classpath = ""
if os.path.exists(lib_dir):
    libs = [os.path.join(lib_dir, f) for f in os.listdir(lib_dir) if f.endswith(".jar")]
    classpath = ";".join(libs) if os.name == 'nt' else ":".join(libs)

src_files = [
    os.path.join(src_dir, "com", "example", "mcchatbridge", "HttpWebServer.java"),
    os.path.join(src_dir, "com", "example", "mcchatbridge", "McChatBridge.java")
]

cmd = [
    javac_path,
    "-d", build_dir,
    "-encoding", "utf-8"
]
if classpath:
    cmd += ["-cp", classpath]

cmd += src_files

print("Compiling mod classes...")
print("Command:", " ".join(cmd))
result = subprocess.run(cmd, capture_output=True, text=True)

print("STDOUT:", result.stdout)
print("STDERR:", result.stderr)

if result.returncode != 0:
    print("Compilation failed! Please make sure JDK is installed and classpath libraries are set correctly.")
    exit(1)
else:
    print("Compilation succeeded.")

# 3. Copy META-INF resources
meta_inf_src = os.path.join(resources_dir, "META-INF")
meta_inf_dst = os.path.join(build_dir, "META-INF")
os.makedirs(meta_inf_dst, exist_ok=True)
shutil.copyfile(
    os.path.join(meta_inf_src, "neoforge.mods.toml"),
    os.path.join(meta_inf_dst, "neoforge.mods.toml")
)
print("Metadata file copied.")

# Copy logo
logo_src = os.path.join(resources_dir, "logo.png")
if os.path.exists(logo_src):
    shutil.copyfile(logo_src, os.path.join(build_dir, "logo.png"))
    print("Logo copied.")

# 4. Create JAR file
print(f"Creating JAR file: {dest_jar}")
if os.path.exists(dest_jar):
    os.remove(dest_jar)

with zipfile.ZipFile(dest_jar, 'w', compression=zipfile.ZIP_DEFLATED) as jar:
    # Walk through the build directory and add files to zip
    for root, dirs, files in os.walk(build_dir):
        for file in files:
            filepath = os.path.join(root, file)
            relpath = os.path.relpath(filepath, build_dir)
            jar.write(filepath, relpath)

print("JAR file successfully created.")
