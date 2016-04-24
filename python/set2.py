import set1
import os
import random
import math
import itertools

def pkcs7padding(text, final_length):
    text_length = len(text)
    padded_length = final_length - text_length

    result = text
    result += bytes([padded_length] * padded_length)

    return result

def aes_cbc_mode_encrypt(text, key, iv):
    BLOCK_SIZE = len(key)
    num_blocks = math.ceil(len(text) / BLOCK_SIZE)
    blocks = []
    for i in range(num_blocks):
        blocks.append( text[(i*BLOCK_SIZE):(i+1)*BLOCK_SIZE] )

    output = b''
    previous_block = iv

    for b in blocks:
        encrypted_block = set1.encrypt_aes_ecb(set1.fixed_xor(previous_block, b), key)
        output += encrypted_block
        previous_block = encrypted_block

    return output

def aes_cbc_mode_decrypt(cipher, key, iv):
    BLOCK_SIZE = len(key)
    num_blocks = math.ceil(len(cipher) / BLOCK_SIZE)
    blocks = []
    for i in range(num_blocks):
        blocks.append(cipher[(i*BLOCK_SIZE):(i+1)*BLOCK_SIZE])

    output = b''
    previous_block = iv

    for b in blocks[0:]:
        decrypted_block = set1.fixed_xor(set1.decrypt_aes_ecb(b, key), previous_block)
        output += decrypted_block
        previous_block = b

    # TODO remove padding length :)

    return output

def encryption_oracle(text):
    # generate 5-10 random bytes before, and 5-10 random bytes after
    before_length = random.randint(5,10)
    before_bytes = os.urandom(before_length)

    after_length = random.randint(5,10)
    after_bytes = os.urandom(after_length)

    # iv / key
    iv = os.urandom(16)
    key = os.urandom(16)

    # nearest 16 length
    def pad(text):
        padded_length = len(text) + (16 - len(text) % 16)
        return pkcs7padding(text, padded_length)

    encrypt_fns = [ ('CBC', lambda text: aes_cbc_mode_encrypt( pad(text), key, iv)), ('ECB', lambda text: set1.encrypt_aes_ecb(pad(text), key)) ]
    mode, fn = random.choice(encrypt_fns)

    # padded length
    random_length_text = before_bytes + text + after_bytes
    length = len(random_length_text)

    return mode, fn(random_length_text)

BLOCK_SIZE = 16
def is_encrypted_aes_ecb(blocks):
    # check if sub blocks of each block are identical to other blocks
    for b1,b2 in itertools.combinations(blocks, 2):
        for sub_block in range(2, BLOCK_SIZE):
            for i in range(BLOCK_SIZE - sub_block):
                print(b1[i:i+sub_block], b2)

    return False

def detection_oracle(encrypted):

    # break each line into 16 byte blocks
    num_blocks = len(encrypted) // BLOCK_SIZE
    blocks = []
    for i in range(num_blocks):
        blocks.append(encrypted[(i*BLOCK_SIZE):((i+1)*BLOCK_SIZE)])

    print(is_encrypted_aes_ecb(blocks))

    ecb = False

    return None
    # return 'ECB' if ecb else 'CBC'

