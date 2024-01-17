import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
import struct
import os

def get_text_section(elf):
    i = 0
    for section in elf.iter_sections():

        if section.name == ".text":
            return section, i
        i = i + 1

def get_text_section_load_segment(elf, text_section):
    i = 0
    for segment in elf.iter_segments():
        if segment.header.p_type == "PT_LOAD" and segment.header.p_vaddr <= text_section.header.sh_addr and segment.header.p_vaddr + segment.header.p_memsz >= text_section.header.sh_addr + text_section.header.sh_size:
            return segment, i
        i = i + 1

def elf_packer(input_file, output_file, num_nops):
    PT_NOTE = 4   # Segment type for PT_NOTE
    PT_LOAD = 1   # Segment type for PT_LOAD

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

        text_section, shdr_text_index = get_text_section(elf)

        text_section_offset = text_section.header.sh_offset
        text_section_size = text_section.header.sh_size
        text_section_addr = text_section.header.sh_addr

        segment_for_text, seg_for_text_index = get_text_section_load_segment(elf, text_section)

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
        print(elf.header.e_phentsize)
        modified_elf_data = bytearray(file.read())



        o_ep = elf.header.e_entry
        new_ep = struct.pack('<Q', 0xc000000+os.stat(input_file).st_size)
        text_section, section_index = get_text_section(elf)
        section_offset = elf.header.e_shoff + section_index * elf.header.e_shentsize

        #crypt text section here
        text_section_data = modified_elf_data[text_section_offset:text_section_offset+text_section_size]
        for c in range(0, len(text_section_data)):
            text_section_data[c] = text_section_data[c] ^ 0xAA
        modified_elf_data[text_section_offset:text_section_offset+text_section_size] = text_section_data
        decrypter = "b8aa000000b9eeeeeeeee8000000005e49b9cccccccccccccccc4c01ce448a064130c044880648ffc648ffc975ef"
        decrypt_addr = struct.pack('<q', text_section_addr - (struct.unpack('<Q', new_ep)[0] + len("b8aa000000b90000")-1))
        print(hex(text_section_size))
        decrypter = decrypter.replace("cccccccccccccccc", decrypt_addr.hex())
        decrypter = decrypter.replace("eeeeeeee", struct.pack('<I', text_section_size).hex())
        decrypter = decrypter.replace("aa", "aa")
        print(decrypter)
        decrypter = bytearray.fromhex(decrypter)



        modified_elf_data[elf.header.e_phoff + seg_for_text_index * elf.header.e_phentsize+4] = 0x7
        modified_elf_data[ph_note_offset:ph_note_offset+elf.header.e_phentsize] = packed_phdr
        modified_elf_data.extend(decrypter)
        jmp_back = b'\xe9' + struct.pack('<i', o_ep - (new_values['p_vaddr'] + len(decrypter) + 5))
        modified_elf_data[24:32] = new_ep
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
