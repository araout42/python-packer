import os
import subprocess
import re

def pack_and_compare_files(num_files, output_file):
    base_filename = "whoami.packed"

    with open(output_file, 'w') as f:
        for i in range(1, num_files + 1):
            packed_filename = f"{base_filename}{i}"
            os.system(f"python3 Packer.py ./whoami -p --key 77; mv whoami.packed {packed_filename}; chmod +x {packed_filename}")

            for j in range(i + 1, num_files + 1):
                compare_files(packed_filename, f"{base_filename}{j}", f)

def compare_files(file1, file2, file_handle):
    cmd = f"radiff2 -C -A {file1} {file2} | grep entry0"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()

    # Regular expression to match and extract the number between parentheses
    pattern = r'\(\s*([0-9.]+)\s*\)'

    for line in stdout.splitlines():
        match = re.search(pattern, line)
        if match:
            print(match.group(1))
            file_handle.write(f"{match.group(1)}\n")

if __name__ == "__main__":
    pack_and_compare_files(10, "entropy_result2")
