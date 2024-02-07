import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
import struct
import os
from miasm.arch.x86.arch import mn_x86
from miasm.core.locationdb import LocationDB
import random
from decryptor import poly_decrypter

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


def elf_packer(input_file, output_file, args):
    PT_NOTE = 4   # Segment type for PT_NOTE
    PT_LOAD = 1   # Segment type for PT_LOAD
    if args.key is None:
        key = random.randint(0, 0xFF)
    else:
        key = int(args.key)
    print("Encrypting with key: '%s'" % hex(key))
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
        modified_elf_data = bytearray(file.read())



        o_ep = elf.header.e_entry
        new_ep = struct.pack('<Q', 0xc000000+os.stat(input_file).st_size)
        text_section, section_index = get_text_section(elf)
        section_offset = elf.header.e_shoff + section_index * elf.header.e_shentsize

        #crypt text section here
        text_section_data = modified_elf_data[text_section_offset:text_section_offset+text_section_size]
        for c in range(0, len(text_section_data)):
            text_section_data[c] = text_section_data[c] ^ key
        modified_elf_data[text_section_offset:text_section_offset+text_section_size] = text_section_data
        decrypt_addr = text_section_addr - struct.unpack('<Q', new_ep)[0]
        decrypter = poly_decrypter(key, len(text_section_data), decrypt_addr, args)
        print("DECRYPTER : "+decrypter)
        decrypter = bytearray.fromhex(decrypter)



        modified_elf_data[elf.header.e_phoff + seg_for_text_index * elf.header.e_phentsize+4] = 0x7
        modified_elf_data[ph_note_offset:ph_note_offset+elf.header.e_phentsize] = packed_phdr
        modified_elf_data.extend(decrypter)
        jmp_back = b'\xe9' + struct.pack('<i', o_ep - (new_values['p_vaddr'] + len(decrypter))-5)
        modified_elf_data[24:32] = new_ep
        modified_elf_data.extend(jmp_back)
    # Write the modified ELF to a new file
    with open(output_file, 'wb') as file:
        file.write(modified_elf_data)

    print(f"ELF file packed: {input_file} -> {output_file}")







