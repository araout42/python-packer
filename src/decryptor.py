from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.core import parse_asm, asmblock
import random
import binascii
from miasm.arch.x86.arch import mn_x86

def extend_ret(table1, table2):
    result = []
    result.extend(table1)
    result.extend(table2)
    return result

def reg_to_sized_reg(registers, reg_number, size):
    reg_maps = [
        {64: "RAX", 32: "EAX", 16: "AX", 8: "AL"},
        {64: "RBX", 32: "EBX", 16: "BX", 8: "BL"},
        {64: "RCX", 32: "ECX", 16: "CX", 8: "CL"},
        {64: "RDX", 32: "EDX", 16: "DX", 8: "DL"},
        {64: "RSI", 32: "ESI", 16: "SI", 8: "SIL"},
        {64: "RDI", 32: "EDI", 16: "DI", 8: "DIL"},
        {64: "RBP", 32: "EBP", 16: "BP", 8: "BPL"},
        {64: "RSP", 32: "ESP", 16: "SP", 8: "SPL"},
        {64: "R8", 32: "R8D", 16: "R8W", 8: "R8B"},
        {64: "R9", 32: "R9D", 16: "R9W", 8: "R9B"},
        {64: "R10", 32: "R10D", 16: "R10W", 8: "R10B"},
        {64: "R11", 32: "R11D", 16: "R11W", 8: "R11B"},
        {64: "R12", 32: "R12D", 16: "R12W", 8: "R12B"},
        {64: "R13", 32: "R13D", 16: "R13W", 8: "R13B"},
        {64: "R14", 32: "R14D", 16: "R14W", 8: "R14B"},
        {64: "R15", 32: "R15D", 16: "R15W", 8: "R15B"},
    ]
    for maps in reg_maps:
        if registers[reg_number] in maps.values():
            return(maps[size])

def get_set_reg_to_0(reg_number, registers):
    set_reg_0 = [
        ["XOR "+registers[reg_number]+", "+registers[reg_number]],
        ["MOV "+registers[reg_number]+", 0x0"],
        ["MOV "+registers[reg_number]+", 0x1", "DEC "+registers[reg_number]],
        ["MOV "+registers[reg_number]+", -0x1", "INC "+registers[reg_number]],
        ["MOV "+registers[reg_number]+", "+hex(random.randrange(50, 10000)), "SHR "+registers[reg_number]+", 0xFF"],
        ["SUB "+registers[reg_number]+", "+registers[reg_number]],
        ["AND "+registers[reg_number]+", 0x0"],
        ["IMUL "+registers[reg_number]+", "+registers[reg_number]+", 0x0"],
        ["IMUL "+registers[reg_number]+", "+registers[reg_number]+", "+hex(random.randrange(50, 10000)),"MOV "+registers[reg_number]+", 0x0"],
        ["PUSH 0x0", "POP "+registers[reg_number]],
        ["SHR "+registers[reg_number]+", 0xFF"],
    ]
    return set_reg_0

def build_block_instruction(asm):
    loc_db = LocationDB()
    asmcfg = parse_asm.parse_txt(mn_x86, 64, asm, loc_db)
    loc_db.set_location_offset(loc_db.get_or_create_name_location("main"), 0x0)
    patches = asmblock.asm_resolve_final(mn_x86, asmcfg)
    result = ""
    for p in patches.values():
        result += binascii.hexlify(p).decode("utf-8")
    return result

def build_instruction(instruction_set, loc_db):
    mn = Machine('x86_64').mn
    instruction = random.choice(instruction_set)
    final_bytes = ""
    for instr in instruction:
        l = mn.fromstring(instr, loc_db, 64)
        a = mn.asm(l)
        hex_string = binascii.hexlify(random.choice(a)).decode("utf-8")
        final_bytes += hex_string
    return final_bytes


def get_rip_vector(decoder, pop_position):
    number = (len(decoder)//2) - pop_position
    number = format(number, 'x')

    while len(number) < 4:
        number = number+ "0"
    return number

def get_reg_preservation(registers, way):
    reg_preservation = []
    if way == "PUSH":
        for reg in registers:
            reg_preservation.append("PUSH "+reg)
        return reg_preservation
    elif way == "POP":
        registers.reverse()
        for reg in registers:
            reg_preservation.append("POP "+reg)
        return reg_preservation


### REGISTER 0 = KEY
### REGISTER 1 = LEN
### REGISTER 2 = RELATIV ADDRESS
### REGISTER 3 = EFFECTIV ADDRESS
### REGISTER 4 = BYTE TO DECRYPT
### REGISTER 5 = REGISTER TO CALL (MUST BE 0)
### REGISTER 6+ = JUNK
def poly_decrypter(key, length, relative_address, args):
    mn = Machine('x86_64').mn
    loc_db = LocationDB()
    registers = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14"]
    random.shuffle(registers)
    print(registers)
    reg0_to_0 = get_set_reg_to_0(0, registers)
    reg1_to_0 = get_set_reg_to_0(1, registers)
    reg2_to_0 = get_set_reg_to_0(2, registers)
    reg3_to_0 = get_set_reg_to_0(3, registers)

    get_key_litteral_set = [
        extend_ret(random.choice(reg0_to_0), ["MOV "+registers[0]+", "+hex(key)]),
        extend_ret(random.choice(reg0_to_0), ["SUB "+registers[0]+", "+hex(key*-1)]),
        extend_ret(random.choice(reg0_to_0), ["ADD "+registers[0]+", "+hex(key)]),
        extend_ret(random.choice(reg0_to_0), ["ADD "+registers[0]+", "+hex(key)]),
        ["MOV "+registers[0]+", "+hex(key)],
        ["PUSH "+hex(key), "POP "+registers[0]],
        extend_ret(random.choice(reg0_to_0), ["SUB "+registers[0]+", "+hex(key*-1)]),
        extend_ret(random.choice(reg0_to_0), ["MOV "+registers[0]+", "+hex(key)]),
        extend_ret(random.choice(reg0_to_0), ["SUB "+registers[0]+", "+hex(key*-1)]),
        extend_ret(random.choice(reg0_to_0), ["ADD "+registers[0]+", "+hex(key)]),
    ]
    get_len_litteral_set = [
        extend_ret(random.choice(reg1_to_0), ["MOV "+registers[1]+", "+hex(length)]),
        extend_ret(random.choice(reg1_to_0), ["SUB "+registers[1]+", "+hex(length*-1)]),
        extend_ret(random.choice(reg1_to_0),[ "ADD "+registers[1]+", "+hex(length)]),
        extend_ret(random.choice(reg1_to_0), ["ADD "+registers[1]+", "+hex(length)]),
        ["MOV "+registers[1]+", "+hex(length)],
        ["PUSH "+hex(length), "POP "+registers[1]],
        extend_ret(random.choice(reg1_to_0), ["SUB "+registers[1]+", "+hex(length*-1)]),
        extend_ret(random.choice(reg1_to_0), ["MOV "+registers[1]+", "+hex(length)]),
        extend_ret(random.choice(reg1_to_0), ["SUB "+registers[1]+", "+hex(length*-1)]),
        extend_ret(random.choice(reg1_to_0), ["ADD "+registers[1]+", "+hex(length)]),
    ]
    get_relative_address_litteral_set = [
        extend_ret(random.choice(reg2_to_0), ["MOV "+registers[2]+", "+hex(relative_address)]),
        extend_ret(random.choice(reg2_to_0), ["SUB "+registers[2]+", "+hex(relative_address*-1)]),
        extend_ret(random.choice(reg2_to_0), ["ADD "+registers[2]+", "+hex(relative_address)]),
        extend_ret(random.choice(reg2_to_0), ["ADD "+registers[2]+", "+hex(relative_address)]),
        ["MOV "+registers[2]+", "+hex(relative_address)],
        extend_ret(random.choice(reg2_to_0), ["SUB "+registers[2]+", "+hex(relative_address*-1)]),
        extend_ret(random.choice(reg2_to_0), ["MOV "+registers[2]+", "+hex(relative_address)]),
        extend_ret(random.choice(reg2_to_0), ["SUB "+registers[2]+", "+hex(relative_address*-1)]),
        extend_ret(random.choice(reg2_to_0), ["ADD "+registers[2]+", "+hex(relative_address)]),
    ]
    r3_to_0 = random.choice(reg3_to_0)[0]
    get_rip_to_reg3_litteral_set = [
        [r3_to_0, "POP "+registers[3], "SUB "+registers[3]+", 0xFAFA"],
    ]
    dec_reg3_5_litteral_set = [
        ["DEC "+registers[3], "DEC "+registers[3], "DEC "+registers[3], "DEC "+registers[3], "DEC "+registers[3]],
        ["SUB "+registers[3]+", 0x5"],
        ["ADD "+registers[3]+", -0x5"],
    ]

    get_rip_bin_set = [
        #"d9e0d97424f4"+build_instruction(get_rip_to_reg3_litteral_set, loc_db),
        #"dfe9d97424f4"+build_instruction(get_rip_to_reg3_litteral_set, loc_db),
        #"dad9d97424f4"+build_instruction(get_rip_to_reg3_litteral_set, loc_db),
        #"dac1d97424f4"+build_instruction(get_rip_to_reg3_litteral_set, loc_db),
        #"dad1d97424f4"+build_instruction(get_rip_to_reg3_litteral_set, loc_db),
        #"dbd9d97424f4"+build_instruction(get_rip_to_reg3_litteral_set, loc_db),
        build_block_instruction('main:\nCALL nexti\nnexti:\nPOP '+registers[3]+'\n'+'\n'.join(random.choice(dec_reg3_5_litteral_set))+'\nSUB '+registers[3]+', 0xFAFA\n'),
    ]

    add_r2_to_r3_litteral_set = [
        ["ADD "+registers[3]+", "+registers[2]],
        ["NEG "+registers[2], "SUB "+registers[3]+", "+registers[2]],
        ["PUSH "+registers[2], "ADD "+registers[3]+", QWORD PTR[RSP]", "POP "+registers[2]],
        ["LEA "+registers[3]+", QWORD PTR["+registers[3]+"+"+registers[2]+"]"],
        ["MOV "+registers[6]+", "+registers[3], "ADD "+registers[6]+", "+registers[2], "MOV "+registers[3]+", "+registers[6]],
    ]
    get_byte_to_xor_litteral_set = [
        ["MOV "+reg_to_sized_reg(registers, 4, 8)+", BYTE PTR["+registers[3]+"]"],

    ]
    xor_r4_to_key_litteral_set = [
        ["XOR "+registers[4]+", "+registers[0]],
        ["PUSH "+registers[4], "XOR QWORD PTR[RSP], "+registers[0], "POP "+registers[4]],
    ]
    mov_r4_to_r3_litteral_set = [
        ["MOV BYTE PTR["+registers[3]+"], "+reg_to_sized_reg(registers, 4, 8)],
        ["MOV BYTE PTR["+registers[3]+"], 0x0", "ADD BYTE PTR["+registers[3]+"], "+reg_to_sized_reg(registers, 4, 8)],
    ]
    increment_r3_litteral_set = [
        ["INC "+registers[3]],
        ["ADD "+registers[3]+", 1"],
        ["SUB "+registers[3]+", -1"],
        ["PUSH 0x1", "ADD "+registers[3]+", QWORD PTR[RSP]", "POP "+registers[6]],
        ["PUSH -0x1", "SUB "+registers[3]+", QWORD PTR[RSP]", "POP "+registers[7]],
    ]
    decrement_r1_litteral_set = [
        ["DEC "+registers[1]],
        ["SUB "+registers[1]+", 1"],
        ["ADD "+registers[1]+", -1"],
    ]
    jump_non_zero_litteral_set = [
        ["JNZ main"],
        ["CMP "+registers[1]+", 0", "JG main"],
    ]


    if args.preserve_register:
        reg_preservation_push = build_instruction([get_reg_preservation(registers, "PUSH")], loc_db)
        reg_preservation_pop = build_instruction([get_reg_preservation(registers, "POP")], loc_db)
    else:
        reg_preservation_push = ""
        reg_preservation_pop = ""


    get_key = build_instruction(get_key_litteral_set, loc_db)
    get_len = build_instruction(get_len_litteral_set, loc_db)
    get_relative_address = build_instruction(get_relative_address_litteral_set, loc_db)
    start_decoder = [get_key, get_len, get_relative_address]
    random.shuffle(start_decoder)

    get_rip = random.choice(get_rip_bin_set)
    final_decoder = reg_preservation_push +  "".join(start_decoder) + get_rip
    final_decoder = final_decoder.replace("fafa", get_rip_vector(final_decoder, len(get_rip)//2))
    final_decoder = final_decoder+build_instruction(add_r2_to_r3_litteral_set, loc_db)

    loop_blocks = 'main:\n\n'+'\n'.join(random.choice(get_byte_to_xor_litteral_set))+'\n'+'\n'.join(random.choice(xor_r4_to_key_litteral_set))+'\n'+'\n'.join(random.choice(mov_r4_to_r3_litteral_set))+'\n'+'\n'.join(random.choice(increment_r3_litteral_set))+'\n'+'\n'.join(random.choice(decrement_r1_litteral_set))+'\n'+'\n'.join(random.choice(jump_non_zero_litteral_set))

    loop_bytes = build_block_instruction(loop_blocks)
    final_decoder = final_decoder + loop_bytes + reg_preservation_pop


    return final_decoder
