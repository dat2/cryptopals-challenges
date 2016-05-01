import set1
import os
import random
import math
import itertools
import base64

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

def detection_oracle(encrypted):
    BLOCK_SIZE = 16

    # break each line into 16 byte blocks
    num_blocks = len(encrypted) // BLOCK_SIZE
    blocks = []
    for i in range(num_blocks):
        blocks.append(encrypted[(i*BLOCK_SIZE):((i+1)*BLOCK_SIZE)])

    return 'ECB' if set1.is_encrypted_aes_ecb(blocks) else 'CBC'

# nearest 16 length
def pad(text):
    padded_length = len(text) + (16 - len(text) % 16)
    return pkcs7padding(text, padded_length)

global_key = os.urandom(16)
random_text = bytes(base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'))
def encrypt_unknown_string_ecb(text):

    # padded length
    random_length_text = text + random_text

    return set1.encrypt_aes_ecb(pad(random_length_text), global_key)

def byte_ecb_decryption(text):

    # discover block_size of cipher
    discovered_block_size = None
    string_size = 1
    while discovered_block_size == None:
        plaintext = bytes('A' * string_size, 'ascii')
        encrypted = encrypt_unknown_string_ecb(plaintext)

        # the starting number is kind of cheating, i know the block size is 16
        # but numbers less than 10 gave me smaller block_sizes
        for block_size in range(10,32):
            # break each line into block_size byte blocks
            num_blocks = len(encrypted) // block_size
            blocks = []
            for i in range(num_blocks):
                blocks.append(encrypted[(i*block_size):((i+1)*block_size)])

            # check if any blocks are the same
            if set1.is_encrypted_aes_ecb(blocks):
                discovered_block_size = block_size
                break

        string_size += 1

    # we have discovered the block_size, we must now detect that it is using
    # ECB
    mode = detection_oracle(text)
    if mode != 'ECB':
        # we are not good :(
        return text

    # we can safely assume it is ECB at this point
    dict_chars = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 !@#$%^&*()-_=+[{]};:\'",<.>/?~`|\\\n'

    decrypted_text = bytearray()
    plaintext_size = discovered_block_size - 1
    current_block = 1
    current_block_size = discovered_block_size

    while len(decrypted_text) != len(random_text):
        # make a dictionary of encrypted back to plain text chars
        encrypted_to_plain = {}
        plaintext = bytes('A' * plaintext_size, 'ascii')

        start_index = (current_block - 1) * discovered_block_size
        end_index = start_index + discovered_block_size

        # get all the blocks of decrypted text up to the current block
        prefix = bytes(plaintext + decrypted_text)

        # map all encrypted versions of characters
        for char in dict_chars:
            input_map = prefix + bytes([char])
            encrypted = encrypt_unknown_string_ecb(input_map)
            last_block = encrypted[start_index:end_index]
            encrypted_to_plain[last_block] = char

        encrypted = encrypt_unknown_string_ecb(plaintext)
        last_block = encrypted[start_index:end_index]
        decrypted_text.append(encrypted_to_plain[last_block])

        current_block_size -= 1
        plaintext_size -= 1

        if current_block_size == 0:
            current_block_size = discovered_block_size
            plaintext_size = discovered_block_size - 1
            current_block += 1

    return bytes(decrypted_text)
