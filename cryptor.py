#!/usr/bin/python3

# Crypts the .secure_code and .secure_data sections of the input ELF file with the same generated key

import json
import sys
import shutil

from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from elftools.elf.elffile import ELFFile

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

def encrypt_section(filename, section_name):
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
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_GCM)
        cipher.update(section_header_data)

        #print (secure_code.header)
        ciphertext, tag = cipher.encrypt_and_digest(section_data)

        assert(len(ciphertext) == section_size)
        print ("All Assertions passed")

        json_k = [ 'nonce', 'ciphertext', 'tag' ]
        json_v = [ b64encode(x).decode('utf-8') for x in [cipher.nonce, ciphertext, tag ]]

        result = json.dumps(dict(zip(json_k, json_v)))
        print (result)
        print ("--Writing %s ciphertext to file--" % section_name)

        return (section['sh_addr'], section_size, tag, cipher.nonce)


def main():
    filename = sys.argv[1]
    code_start_virt_addr, code_size, code_tag, code_nonce = encrypt_section(filename, '.secure_code')
    data_start_virt_addr, data_size, data_tag, data_nonce = encrypt_section(filename, '.secure_data')
    #fill_in_constants(code_start_virt_addr, code_size, code_tag,
    #       data_start_virt_addr, data_size, data_tag)

if __name__ == '__main__':
    main()
