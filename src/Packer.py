from pack_elf import elf_packer
from pack_pe import pe_packer
import argparse
import os


def infile_format(file_path):
    with open(file_path, 'rb') as f:
        header = f.read(4)
        if header == b'\x7fELF':
            return "ELF"
        elif header[0:2] == b'MZ':
            return "PE"
        else:
            return "UNKNOWN"

def main():
    parser = argparse.ArgumentParser(description='Parsing arguments for Packer')
    parser.add_argument('--key', type=int, default=None, help='Key for decryption')
    parser.add_argument('--preserve-register', '-p', action='store_true',
                    help='Option to preserve the register.')
    parser.add_argument('file_path', type=str, help='The path to the file to process.')
    args = parser.parse_args()
    if not os.path.exists(args.file_path):
        print(f"The specified file does not exist: {args.file_path}")
        exit(1)
    input_file = args.file_path
    output_file = input_file+".packed"
    if infile_format(input_file) == "ELF":
        elf_packer(input_file, output_file, args)
    elif infile_format(input_file) == "PE":
        pe_packer(input_file, output_file, args)
    else:
        print(f"Unsupported file format: {input_file}")
    return 0

if __name__ == "__main__":
    main()
