import os
import subprocess

def pack_and_compare_files(num_files):
    base_filename = "whoami.packed"

    # Generate packed files
    for i in range(1, num_files + 1):
        packed_filename = f"{base_filename}{i}"
        # Run your packing command
        os.system(f"python3 Packer.py ./whoami -p; mv whoami.packed {packed_filename}")

        # Compare the current packed file with all subsequent ones
        for j in range(i + 1, num_files + 1):
            compare_files(packed_filename, f"{base_filename}{j}")

def compare_files(file1, file2):
    # Run radiff2 command and grep for 'entry0'
    cmd = f"radiff2 -C -A {file1} {file2} 2>/dev/null | grep entry0"
    result = subprocess.run(cmd, shell=True, text=True, capture_output=True)

    # Output the comparison result
    print(f"Comparing {file1} with {file2}:")
    print(result.stdout)

if __name__ == "__main__":
    pack_and_compare_files(1000)
