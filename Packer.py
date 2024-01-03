import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
import struct
import os

def elf_packer(input_file, output_file, num_nops):
    PT_NOTE = 4   # Segment type for PT_NOTE
    PT_LOAD = 1   # Segment type for PT_LOAD
    NOP = 0x90    # NOP instruction for x86 architecture

    with open(input_file, 'rb') as file:
        elf = ELFFile(file)

        # Ensure the file is a 64-bit ELF
        if not elf.elfclass == 64:
            print("This is not a 64-bit ELF file.")
            return

        # Read the program headers
        ph_note = None
        i = 0
        for segment in elf.iter_segments():
            i = i+1
            if segment.header.p_type == "PT_NOTE":
                ph_note = segment
                ph_note_offset = elf.header.e_phoff + (i-1) * elf.header.e_phentsize
                break

        if ph_note is None:
            print("No PT_NOTE segment found.")
            return

        #Modify the segment type to PT_LOAD and flags
        new_values = dict()
        print(new_values)
        new_values['p_type'] = 0x1
        new_values['p_flags'] = ph_note.header.p_flags | 5  # Set executable and readable flags
        new_values['p_offset']  = os.stat(input_file).st_size
        new_values['p_vaddr'] = 0xc000000+os.stat(input_file).st_size
        new_values['p_paddr'] = 0xc000000+os.stat(input_file).st_size
        new_values['p_filesz'] = ph_note.header.p_filesz + 0x1000
        new_values['p_memsz'] = ph_note.header.p_memsz + 0x1000
        new_values['p_align'] = ph_note.header.p_align

        packed_phdr = struct.pack(
            '<IIQQQQQQ',
            new_values['p_type'],
            new_values['p_flags'],
            new_values['p_offset'],
            new_values['p_vaddr'],
            new_values['p_paddr'],
            new_values['p_filesz'],
            new_values['p_memsz'],
            new_values['p_align']
        )

        # Prepare the modified ELF data
        file.seek(0)
        decoder_size = 0x100
        print(elf.header.e_phentsize)
        modified_elf_data = bytearray(file.read())
        modified_elf_data[ph_note_offset:ph_note_offset+elf.header.e_phentsize] = packed_phdr
        modified_elf_data.extend(b'\x90' * 0x100)
        o_ep = elf.header.e_entry
        jmp_back = b'\xe9' + struct.pack('<i', o_ep - (new_values['p_vaddr'] + decoder_size + 5))
        modified_elf_data[24:32] = struct.pack('<Q', 0xc000000+os.stat(input_file).st_size)
        modified_elf_data.extend(jmp_back)
    # Write the modified ELF to a new file
    with open(output_file, 'wb') as file:
        file.write(modified_elf_data)

    print(f"ELF file packed: {input_file} -> {output_file}")

if len(sys.argv) >1:
    input_elf = sys.argv[1]
else:
    exit("Usage: python3 Packer.py <input_elf> ")
output_elf = input_elf+".packed"

number_of_nops = 10
elf_packer(input_elf, output_elf, number_of_nops)
