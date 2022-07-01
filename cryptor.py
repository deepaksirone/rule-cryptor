#!/usr/bin/python3

# Crypts the .secure_code and .secure_data sections of the input ELF file with the same generated key

import json
import sys
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

def encrypt_code(filename):
    with open(filename, 'rb+') as f:
        elf = ELFFile(f)
        secure_code = elf.get_section_by_name('.secure_code')
        assert(secure_code != None)

        secure_code_size = secure_code['sh_size']
        assert(secure_code_size % 4096 == 0)

        secure_code_offset = secure_code['sh_offset']
        secure_code_section_index = elf.get_section_index('.secure_code')
        secure_code_header_offset = elf._section_offset(secure_code_section_index)

        secure_code_header_data = get_section_header_bytes(filename, secure_code_header_offset)
        print ("Secure_code_header_offset: %d" % secure_code_header_offset)
        print (secure_code_header_data)
        secure_code_data = secure_code.data()

        assert(len(secure_code_data) == secure_code_size)
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_GCM)
        cipher.update(secure_code_header_data)

        print (secure_code.header)
        ciphertext, tag = cipher.encrypt_and_digest(secure_code_data)

        assert(len(ciphertext) == secure_code_size)
        print ("All Assertions passed")

        json_k = [ 'nonce', 'ciphertext', 'tag' ]
        json_v = [ b64encode(x).decode('utf-8') for x in [cipher.nonce, ciphertext, tag ]]

        result = json.dumps(dict(zip(json_k, json_v)))
        print (result)
        print ("--Writing .secure_code ciphertext to file--")

        return (secure_code['sh_addr'], secure_code_size, tag)


def main():
    filename = sys.argv[1]
    code_start_virt_addr, code_size, code_tag = encrypt_code(filename)
    #data_start_virt_addr, data_size, data_tag = encrypt_data(filename)
    #fill_in_constants(code_start_virt_addr, code_size, code_tag,
    #       data_start_virt_addr, data_size, data_tag)

if __name__ == '__main__':
    main()
