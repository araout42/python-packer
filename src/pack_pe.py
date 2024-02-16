import lief
from decryptor import poly_decrypter
import random
import struct

def adjust_SectionSize(sz, align):
  if sz % align: sz = ((sz + align) // align) * align
  return sz



def find_code_cave(pe):
    for section in pe.sections:
        if section.name == ".text":
            return section
    return None

def get_text_section(binary):
    for section in binary.sections:
        if section.name == ".text":
            return section
    return None

def extend_text_section(text_section, size, decrypter):
    text_section.virtual_size += size
    text_section.size += size
    data = bytearray(text_section.content)
    data += decrypter
    new_data_int_list = list(data)
    text_section.content = new_data_int_list


def write_file(binary, filename):
    binary.write(filename+".exe")
    print("Packed file written to", filename+".exe")
    return filename

def get_decrypter(key, size, old_ep, new_ep, args):
    decrypt_addr = old_ep - new_ep
    decrypter = poly_decrypter(key, size, old_ep, args)
    print("Decrypter:", decrypter)
    decrypter = bytearray.fromhex(decrypter)
    jmp_back = b'\xe9' + struct.pack('<i', old_ep - (new_ep + len(decrypter))-5)
    decrypter.extend(jmp_back)
    return decrypter



def pe_packer(input_file, output_file, args):
    if args.key is None:
        key = random.randint(0, 0xFF)
    else:
        key = int(args.key)
    binary = lief.parse(input_file)
    text_section = get_text_section(binary)
    text_section_size = text_section.size
    new_ep = text_section.virtual_address + text_section.virtual_size
    old_ep = binary.optional_header.addressof_entrypoint
    print("New entry point:", hex(new_ep))
    print("Old entry point:", hex(old_ep))
    decrypter = get_decrypter(key, text_section_size, old_ep, new_ep,  args)
    extend_text_section(text_section, len(decrypter)+5, decrypter)

    binary.optional_header.addressof_entrypoint = new_ep
    write_file(binary, output_file)







