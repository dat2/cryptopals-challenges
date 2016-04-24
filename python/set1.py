import binascii
from collections import Counter
import operator as op
from Crypto.Cipher import AES
import itertools

def hex_to_base64(h):
    return binascii.b2a_base64(h)[:-1]

def fixed_xor(a_bytes, b_bytes):
    result_bytes = []

    for (a_i, b_i) in zip(a_bytes, b_bytes):
        result_bytes.append(a_i ^ b_i)

    return bytes(result_bytes)

english_letter_frequency = Counter(
    e = 0.12702,
    t = 0.09056,
    a = 0.08167,
    o = 0.07507,
    i = 0.06966,
    n = 0.06749,
    s = 0.06327,
    h = 0.06094,
    r = 0.05987,
    d = 0.04253,
    l = 0.04025,
    c = 0.02782,
    u = 0.02758,
    m = 0.02406,
    w = 0.02361,
    f = 0.02228,
    g = 0.02015,
    y = 0.01974,
    p = 0.01929,
    b = 0.01492,
    v = 0.00978,
    k = 0.00772,
    j = 0.00153,
    x = 0.00150,
    q = 0.00095,
    z = 0.00074
)

def make_letter_distribution(text):

    # copy the english_letter_frequency
    freq_distro = {}
    for key in english_letter_frequency:
        freq_distro[key] = 0

    # if the character is english letter, then we count it
    total = 0
    penalty = 0
    for char in text:
        if chr(char).lower() in freq_distro:
            freq_distro[chr(char).lower()] += 1
            total += 1

        # spaces don't incur a penalty
        elif char != ord(' '):
            penalty += 1

    if total == 0:
        return None, 0

    # normalize the distribution
    for key in freq_distro.keys():
        freq_distro[key] /= total

    return freq_distro, penalty

def english_error(text):
    distro, penalty = make_letter_distribution(text)
    if distro == None:
        return None

    total_error = 0
    for letter in distro:
        total_error += abs(distro[letter] - english_letter_frequency[letter])

    return total_error + penalty

def decipher_singlebyte_xor(encrypted):
    '''
    Encrypted must be a bytes literal
    returns a byte literal
    '''
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*() :'

    encrypted_len = len(encrypted)

    errors = []
    decrypted = []
    for c in chars:
        hex_str = bytes(c * encrypted_len, 'ascii')
        decrypted_bytes = fixed_xor(hex_str, encrypted)
        error = english_error(decrypted_bytes)

        if(error != None):
            errors.append(error)
            decrypted.append(decrypted_bytes)

    max_index = errors.index(min(errors))

    result = decrypted[max_index]
    error = errors[max_index]
    char = chars[max_index]

    return result, error, char

def detect_singlebyte_xor(lines):
    results = []
    for index, line in enumerate(lines):
        deciphered, error, char = decipher_singlebyte_xor(bytes.fromhex(line.strip()))
        results.append( (deciphered, error, char) )

    result = min(results, key=op.itemgetter(1))
    return result

def repeating_key_xor(text, key):

    # repeat the key as long as text is
    # if the text length is not an exact multiple of key length,
    # just chop off the rest of the key repeated string that is longer than text
    length = len(text) // len(key)
    rest = len(text) % len(key)

    key_repeated = bytes()
    for i in range(length):
        key_repeated += key

    key_repeated += key[:rest]

    # then xor it with text
    return fixed_xor(text, key_repeated)


def hamming_distance(a, b):
    '''
    A and b must be byte literals
    '''
    total_dist = 0
    for a,b in zip(list(a),list(b)):
        # convert them to binary
        a_bits = format(a, '08b')
        b_bits = format(b, '08b')

        # count the number of differing bits
        for a_bit, b_bit in zip(a_bits, b_bits):
            if a_bit != b_bit:
                total_dist += 1

    return total_dist

def break_repeating_key_xor(encrypted):

    # find the keysizes with the smallest edit distance as likely candidates
    edit_distances = []
    for key_size in range(15,40):
        a = encrypted[:key_size]
        b = encrypted[key_size:key_size * 2]
        c = encrypted[key_size * 2:key_size * 3]
        d = encrypted[key_size * 3:key_size * 4]
        e = encrypted[key_size * 4:key_size * 5]
        f = encrypted[key_size * 5:key_size * 6]
        avg_edit_distance = (hamming_distance(a,b) + hamming_distance(c,d) + hamming_distance(e,f)) / 3

        edit_distances.append( (key_size, avg_edit_distance / key_size) )

    # sort keysize by minimum edit_distance
    likely_keysizes = list(map(op.itemgetter(0), sorted(edit_distances, key=op.itemgetter(1))))

    final_deciphered = []

    # finally, find the key for each keysize
    for key_size in likely_keysizes:
        # break encrypted text into blocks
        num_blocks = len(encrypted) // key_size
        blocks = []
        for i in range( num_blocks ):
            blocks.append( encrypted[i*key_size:(i+1)*key_size] )

        # transpose these blocks
        transposed_blocks = [b''] * key_size
        for k in range(key_size):
            for i in range( num_blocks ):
                transposed_blocks[k] += blocks[i][k:k+1]

        # finally, decrypt them
        key =  b''
        for block in transposed_blocks:
            deciphered, error, char = decipher_singlebyte_xor(block)
            key += bytes(char, 'ascii')

        # try deciphering
        deciphered = repeating_key_xor(encrypted,key)
        error = english_error(deciphered)
        final_deciphered.append( (deciphered, key, error) )

    result = min(final_deciphered, key=op.itemgetter(2))

    return result

def decrypt_aes_ecb(text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(text)

def encrypt_aes_ecb(text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(text)

BLOCK_SIZE = 16
def is_encrypted_aes_ecb(blocks):
    # check if sub blocks of each block are identical to other blocks
    for b1,b2 in itertools.combinations(blocks, 2):
        if(b1 == b2):
            return True

    return False

def detect_aes_ecb(lines):
    numbers = []
    for line_number, line in enumerate(lines):
        bs = bytes.fromhex(line.strip())

        # break each line into 16 byte blocks
        num_blocks = len(bs) // BLOCK_SIZE
        blocks = []
        for i in range(num_blocks):
            blocks.append(bs[(i*BLOCK_SIZE):((i+1)*BLOCK_SIZE)])

        # if there are similarities in the message, then there will
        # be similarities in the AES_ECB line
        if is_encrypted_aes_ecb(blocks):
            numbers.append(line_number + 1)

    return numbers


