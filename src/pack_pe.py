import lief
from lief import PE
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
    #text_section.virtual_size += size
    #text_section.size += size
    text_section.characteristics = text_section.characteristics | lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
    print("Text section size:", text_section)
    data = bytearray(text_section.content)
    data += decrypter
    new_data_int_list = list(data)
    text_section.content = data

def write_file(binary, filename):
    binary.write(filename+".exe")
    print("Packed file written to", filename+".exe")
    return filename

def get_decrypter(key, size, old_ep, new_ep,text_section, args):
    decrypt_addr = old_ep - new_ep
    decrypter = poly_decrypter(key, size, text_section.virtual_address-new_ep, args)
    print("Decrypter:", decrypter)
    decrypter = bytearray.fromhex(decrypter)
    jmp_back = b'\xe9' + struct.pack('<i', old_ep - (new_ep + len(decrypter))-5)
    decrypter.extend(jmp_back)
    return decrypter

def encode_text(text_section, key):
    encrytped_text_section = bytearray(text_section.content)
    for i in range(len(encrytped_text_section)):
        encrytped_text_section[i] ^= key
    return encrytped_text_section


def get_tls_content(callbacks, tlsoffsets, text_section):
    tls_content = []
    for i in range( len(tlsoffsets)):
        tls_content.append(bytearray())
        txt = text_section.content[tlsoffsets[i]:-1]
        for byte in txt:
            tls_content[i].append(byte)
            if hex(byte) == '0x90':
                break
    return tls_content

def tls_work(binary, new_ep, key):
    tls = binary.tls
    tls_content = []
    callbacks = list(tls.callbacks)
    text_section = get_text_section(binary)
    for callback in callbacks:
        print("Callback:", hex(callback))
        print(hex(binary.rva_to_offset(callback)))
    print(hex(text_section.virtual_address + binary.optional_header.imagebase))
    text_sect_start = text_section.virtual_address + binary.optional_header.imagebase
    tlsoffsets = []
    for callback in callbacks:
        tlsoffsets.append(callback - text_sect_start)
    tls_content = get_tls_content(callbacks, tlsoffsets, text_section)
    print("TLS Content:", tls_content)
    content = bytearray(text_section.content)
    for i in range(len(tls_content)):
        for k in range(len(content[tlsoffsets[i]:tlsoffsets[i]+len(tls_content[i])])):
            content[tlsoffsets[i]+k] ^= keyold_ep
    text_section.content = content
    print("TLS Content:", get_tls_content(callbacks, tlsoffsets, text_section))


def pe_packer(input_file, output_file, args):
    if args.key is None:
        key = random.randint(0, 0xFF)
    else:
        key = int(args.key)
    binary = lief.parse(input_file)
    text_section = get_text_section(binary)
    text_section_size = text_section.size
    new_ep = text_section.virtual_address + text_section.virtual_size
    print("New EP:", hex(new_ep+binary.optional_header.imagebase))
    old_ep = binary.optional_header.addressof_entrypoint
    print("Old EP:", hex(old_ep+binary.optional_header.imagebase))
    #tls = tls_work(binary, new_ep+binary.optional_header.imagebase, key)
    text_section.content = encode_text(text_section, key)
    decrypter = get_decrypter(key, len(text_section.content), old_ep, new_ep, text_section,  args)
    extend_text_section(text_section, len(decrypter)+5, decrypter)
    binary.optional_header.addressof_entrypoint = new_ep
    write_file(binary, output_file)







