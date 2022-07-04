#!/usr/bin/python3

# Crypts the .secure_code and .secure_data sections of the input ELF file with the same generated key

import json
import sys
import shutil

from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from elftools.elf.elffile import ELFFile

def fill_constant(filename, constant_name, constant_value):
    with open(filename, 'rb+') as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name('.symtab')
        constant_starts = symtab.get_symbol_by_name(constant_name)
        assert(constant_starts != None)
        constant_start = constant_starts[0]

        assert(constant_start != None)

        #Get virt address of symbol
        abs_const_start = constant_start['st_value']

        #Get section where the symbol lives
        section_idx = constant_start['st_shndx']
        sym_section = elf.get_section(section_idx)

        #Compute file offset of section
        section_file_offset = sym_section['sh_offset']
        section_virt_addr = sym_section['sh_addr']
        symbol_file_offset = abs_const_start - section_virt_addr + section_file_offset

        #TODO: convert values to int or bytes and write it to the file
        if isinstance(constant_value, int):
            f.seek(symbol_file_offset)
            prev_val = int.from_bytes(f.read(8), 'little')
            print ("Rewriting const value: %s having val %s with Integer Constant: %d" % (constant_name, hex(prev_val), constant_value))
            print ("Assuming 64-bit values")
            buf = constant_value.to_bytes(8, 'little')
            f.seek(symbol_file_offset)
            f.write(buf)
        else:
            assert(len(constant_value) == 8)
            f.seek(symbol_file_offset)
            prev_val = int.from_bytes(f.read(8), 'little')
            print ("Rewriting const value %s having val %s with Buffer Value: %s" % (constant_name, hex(prev_val), str(constant_value)))
            f.seek(symbol_file_offset)
            f.write(constant_value)
        f.close()

def get_section_header_bytes(filename, offset):
    with open(filename, 'rb+') as f:
        f.seek(offset)
        ret = f.read(0x40)
        f.close()
        return ret

def write_to_file(filename, data, offset):
    with open(filename, 'rb+') as f:
        f.seek(offset)
        f.write(data)
        f.close()

def encrypt_section(filename, section_name, key):
    with open(filename, 'rb+') as f:
        elf = ELFFile(f)
        section = elf.get_section_by_name(section_name)
        assert(section != None)

        section_size = section['sh_size']
        assert(section_size % 4096 == 0)

        section_offset = section['sh_offset']
        section_index = elf.get_section_index(section_name)
        section_header_offset = elf._section_offset(section_index)

        section_header_data = get_section_header_bytes(filename, section_header_offset)
        #print ("Section_header_offset: %d" % secure_code_header_offset)
        #print (secure_code_header_data)
        section_data = section.data()

        assert(len(section_data) == section_size)
        # key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_GCM)
        #cipher.update(section_header_data)

        #print (secure_code.header)
        ciphertext, tag = cipher.encrypt_and_digest(section_data)

        assert(len(ciphertext) == section_size)
        print ("All Assertions passed")

        json_k = [ 'nonce', 'tag' ]
        json_v = [ b64encode(x).decode('utf-8') for x in [cipher.nonce, tag ]]

        result = json.dumps(dict(zip(json_k, json_v)))
        print (result)
        print ("--Writing %s ciphertext to file--" % section_name)
        f.seek(section_offset)
        f.write(ciphertext)

        f.close()

        return (section['sh_addr'], section_size, tag, cipher.nonce)

def fill_in_constants(filename_enc, var_dict):
    for var_name in var_dict:
        fill_constant(filename_enc, var_name, var_dict[var_name])

def main():
    filename = sys.argv[1]
    filename_enc = filename + ".enc"
    shutil.copy2(filename, filename_enc)

    key = get_random_bytes(16)
    code_start, code_size, code_tag, code_nonce = encrypt_section(filename_enc, '.secure_code', key)
    data_start, data_size, data_tag, data_nonce = encrypt_section(filename_enc, '.secure_data', key)
    var_dict = { '__secure_code_start': code_start, '__secure_code_size': code_size, '__secure_code_tag_lower': code_tag[:8], '__secure_code_tag_upper': code_tag[8:],
            '__secure_code_nonce_lower': code_nonce[:8], '__secure_code_nonce_upper': code_nonce[8:], '__secure_data_start': data_start, '__secure_data_size': data_size, '__secure_data_tag_lower': data_tag[:8], '__secure_data_tag_upper': data_tag[8:], '__secure_data_nonce_lower': data_nonce[:8], '__secure_data_nonce_upper': data_nonce[8:], '__dec_key_lower': key[:8], '__dec_key_upper': key[8:]}
    print (var_dict)
    fill_in_constants(filename_enc, var_dict)

    print (key)

if __name__ == '__main__':
    main()
