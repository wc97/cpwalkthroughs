from Crypto.Cipher import AES
from Crypto.Random import random
from numpy.random import randint
from Crypto.Util import number
import base64
import sha1


def bitwise_xor(a, b):
    """Returns the bitwise XOR of two byte vectors: a and b"""

    c = [(a ^ b) for a, b in zip(a, b)]

    return(bytes(c))


def count_chars(s, chars):
    """
    Counts the number of occurences of a given list of characters within
    string, s
    """

    counts = {c: s.count(c) for c in chars}
    total = sum(counts.values())

    return(total)


def score_english(data):
    """
    Very simple function that counts the number of occurences of characters
    from the Alphabet and common punctuation in a string.
    """

    goodChars = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.,! '
    count = count_chars(data, goodChars)

    return(count-(len(data)-count))


def argmax(some_list):
    """Replicates the numpy.argmax for a python list (or other iterable)"""
    return(max(range(len(some_list)), key=lambda x: some_list[x]))


def argmin(some_list):
    """Replicates the numpy.argmin for a python list (or other iterable)"""
    return(min(range(len(some_list)), key=lambda x: some_list[x]))


def break_single_char_XOR(encoded_bv):
    """
    Implements the solution to Set 1, Problem 3

    Given a hex-encoded string that was XOR'd against a single character,
    will search for the "key" and return it along with the decoded
    message.
    """
    score_vec = [0]*256

    for ii in range(0, 256):
        decoded_bv = bitwise_xor(encoded_bv, [ii] * len(encoded_bv))
        score_vec[ii] = score_english(decoded_bv)

    correct_key = argmax(score_vec)
    decoded_bv = bitwise_xor(encoded_bv, [correct_key] * len(encoded_bv))

    return (correct_key, decoded_bv)


def encrypt_repeating_key_XOR(plaintext, key):
    """
    Implements the colution to Set 1, Problem 5

    Encrypts plaintext by XOR'ing it with key repeated to match length of the
    plaintext.
    """

    keystream = (key*round(len(plaintext)/len(key)))[:len(plaintext)+1]
    ciphertext = bitwise_xor(plaintext, keystream)

    return(ciphertext)


def hamming_distance(a, b):
    """Return the hamming (edit) distance between two byte strings"""

    HD = 0
    for ii in range(len(a)):
        HD += bin(a[ii] ^ b[ii]).count('1')

    return(HD)


def detect_AES_ECB(ciphertext, blockSize=16):
    """
    Checks a given ciphertext for any duplicate blocks of data.  If two
    output blocks are identical, it's a good indication that ECB mode
    was used to encrypt.
    """

    CT_Blocks = [ciphertext[ii:ii+blockSize] for ii in
                 range(0, len(ciphertext), blockSize)]

    for ii in range(0, len(CT_Blocks)-1):
        for jj in range(ii+1, len(CT_Blocks)):
            if CT_Blocks[ii] == CT_Blocks[jj]:
                return(True)

    # Didn't find any matching blocks...ECB not detected
    return(False)


def detect_AES_ECB_adjacent(ciphertext, blockSize=16):
    """
    Checks a given ciphertext for any ADJACENT duplicate blocks of
    data.  If two output blocks are identical, it's a good indication
    that ECB mode was used to encrypt.
    """
    CT_Blocks = [ciphertext[ii:ii+blockSize] for ii in
                 range(0, len(ciphertext), blockSize)]

    for block_idx in range(len(CT_Blocks)-1):
        if CT_Blocks[block_idx] == CT_Blocks[block_idx+1]:
            return block_idx

    return(-1)


def PKCS7_pad(data, blocksize=16):
    """
    Returns PKCS7 padded data for a given input and block size.
    """

    if (len(data) % blocksize) != 0:
        pad_length = blocksize - (len(data) % blocksize)
    else:
        pad_length = 16

    if isinstance(data, str):
        data += chr(pad_length) * pad_length
    elif isinstance(data, bytes):
        data += bytes(list([pad_length])) * pad_length
    elif isinstance(data, list):
        data += [pad_length] * pad_length
    else:
        assert(f'Unsupported data type {type(data)} passed to PKCS7Pad')
    return(data)


def strip_PKCS7_pad(data):
    """
    Function to remove PKCS#7 padding from a string.
    Raise an exception on invalid padding.
    """
    if data[-data[-1]:].count(data[-1]) == data[-1]:
        return(data[:-data[-1]])
    else:
        raise(ValueError('Bad PKCS#7 Padding'))


def AESEncrypt(plaintext, key, mode='ECB', IV=[0]*16):

    if mode != 'CTR':
        plaintext = PKCS7_pad(plaintext, 16)

    blockSize = 16
    ciphertext = b''

    aes = AES.new(key, AES.MODE_ECB)

    if mode == 'ECB':

        ciphertext = aes.encrypt(plaintext)

    elif mode == 'CBC':

        PT_Blocks = [plaintext[ii:ii+blockSize] for ii in
                     range(0, len(plaintext), blockSize)]

        for block in PT_Blocks:

            AES_input = bitwise_xor(block, IV)
            IV = aes.encrypt(AES_input)
            ciphertext += IV

    elif mode == 'CTR':

        if (len(IV) == 16) and (IV == [0]*16):
            # If all zeros nonce or none was passed in, set it to 8 x 0's
            IV = [0]*8

        elif len(IV) != 8:

            raise(ValueError('Nonce must be 8 bytes for CTR mode'))

        nonce = IV
        PT_Blocks = [plaintext[ii:ii+blockSize] for ii in
                     range(0, len(plaintext), blockSize)]

        for blk_idx, block in enumerate(PT_Blocks):

            AES_input = bytes(nonce) + int.to_bytes(blk_idx, 8, 'little')
            block_KEY = aes.encrypt(AES_input)
            ciphertext += bitwise_xor(block_KEY[0:len(block)], block)

    else:

        assert(f'Mode {mode} is not supported yet!')

    return(ciphertext)


def AESDecrypt(ciphertext, key, mode='ECB', IV=[0]*16):

    blockSize = 16
    plaintext = b''

    aes = AES.new(key, AES.MODE_ECB)

    if mode == 'ECB':

        return(aes.decrypt(ciphertext))

    elif mode == 'CBC':

        CT_Blocks = [ciphertext[ii:ii+blockSize] for ii in
                     range(0, len(ciphertext), blockSize)]

        for block in CT_Blocks:

            AES_output = aes.decrypt(block)
            plaintext += bitwise_xor(AES_output, IV)
            IV = block

    elif mode == 'CTR':

        # Decrypt is the same as encrypt!
        plaintext = AESEncrypt(ciphertext, key, mode, IV)

    else:

        assert(f'Mode {mode} is not supported yet!')

    return(plaintext)


def encryption_oracle(data):
    """
    Implements Set 2, Challenge 11 - Encryption Oracle

    Emulates an accessible function that will encrypt user-provided data
    under an unknown (random) key.

    For the purposes of this exercise, it randomly selects between ECB
    and CBC mode and returns the "truth"

    Data about what mode was used so we can see if we correctly detect it...
    """

    key = bytes(list(randint(0, 256, 16)))
    mode = randint(0, 2)
    prepend_data = bytes(list(randint(0, 256, randint(5, 11))))
    append_data = bytes(list(randint(0, 256, randint(5, 11))))

    data = prepend_data + data + append_data

    if mode == 0:

        true_mode = 'CBC'
        ciphertext = AESEncrypt(data, key, 'CBC')

    elif mode == 1:

        true_mode = 'ECB'
        ciphertext = AESEncrypt(data, key, 'ECB')

    return(ciphertext, true_mode)


def encryption_oracle_2(data, unknown_key):
    """
    Implement this (encryption oracle for Challenge #12)
    AES-128-ECB(data || unknown-string, random-key)
    """

    unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc\
                      28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZG\
                      J5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5\
                      vLCBJIGp1c3QgZHJvdmUgYnkK"

    unknown_bytes = base64.b64decode(unknown_string)
    AES_input = data + unknown_bytes

    return(AESEncrypt(AES_input, unknown_key))


def encryption_oracle_3(data, key, random_prefix):

    unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc\
                      28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZG\
                      J5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5\
                      vLCBJIGp1c3QgZHJvdmUgYnkK"

    AES_input = random_prefix + data + base64.b64decode(unknown_string)

    return(AESEncrypt(AES_input, key))


def profile_for(email_address):
    """
    For Challenge #13 (Set #2)
    """

    email_address = email_address.replace('=', '')
    email_address = email_address.replace('&', '')
    return('email=' + email_address + '&uid=10&role=user')


def parse_structured_cookie(data):
    """
    For Challenge #13 (Set #2)
    I parse the supplied data and return as a Python dictionary
    """
    new_dict = {}
    split_data = data.split('&')

    for data_def in split_data:

        left_right = data_def.split('=')
        new_dict[left_right[0]] = left_right[1]

    return(new_dict)


def compute_sha1_padding(data):

    # Let's assume message / data is always complete bytes, no extra bits,
    # so always append 0x80
    msg_len = len(data)

    # Pad with 0’s until message is 64-bits less than some multiple of 512
    # (64 in bytes)
    n_zero_bytes = ( (56 - ( (msg_len % 64) + 1) ) % 64 )

    padding = b'\x80' + b'\x00'*n_zero_bytes + (msg_len*8).to_bytes(8, 'big')
    return(padding)


def compute_md4_padding(data):

    # Let's assume message / data is always complete bytes, no extra bits,
    # so always append 0x80
    msg_len = len(data)

    # Pad with 0’s until message is 64-bits less than some multiple of 512
    # (64 in bytes)
    n_zero_bytes = ( (56 - ( (msg_len % 64) + 1) ) % 64 )

    padding = b'\x80' + b'\x00'*n_zero_bytes + \
              (msg_len*8).to_bytes(8, 'little')

    return(padding)


def egcd(a, b):

    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = b, a

    while r != 0:

        q = old_r // r
        old_r, r = r, (old_r - q*r)
        old_s, s = s, (old_s - q*s)

    return(old_r, old_s, old_t)


def invmod(a, m):

    g, x, y = egcd(a, m)

    while x < 0:
        x += m

    return(x % m)


def genRSA_keypair(keysize):

    p = number.getStrongPrime(keysize, e=3)
    q = number.getStrongPrime(keysize, e=3)

    n = (p * q)

    et = (p-1) * (q-1)
    e = 3

    d = invmod(e, et)

    return(e, d, n)


def root(root, b):
    
    if b < 2:
        return b
    a1 = root - 1
    c = 1
    d = (a1 * c + b // (c ** a1)) // root
    e = (a1 * d + b // (d ** a1)) // root
    while c not in (d, e):
        c, d, e = d, e, (a1 * e + b // (e ** a1)) // root
    return min(d, e)


def gen_DSA_sig(x, m, p, q, g):

    k = random.randint(0, q-1)
    
    r = pow(g, k, p) % q
    sha_out = sha1.SHA1(m).finish()
    sha_int = int(sha_out.hex(), 16)
    s = (invmod(k, q) * (sha_int + x*r)) % q
    
    return(r, s, k)


def gen_DSA_sig_given_k(x, m, p, q, g, k):
   
    r = pow(g, k, p) % q
    sha_out = sha1.SHA1(m).finish()
    sha_int = int(sha_out.hex(), 16)
    s = (invmod(k, q) * (sha_int + x*r)) % q
    
    return(r, s)


def check_DSA_sig(m, y, r, s, p, g, q):
    
    w = invmod(s, q)
    sha_out = sha1.SHA1(m).finish()
    sha_int = int(sha_out.hex(), 16)
    u1 = (sha_int * w) % q
    u2 = (r*w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    
    return(v==r)


def dsa_priv_key_from_k(m, k, r, s, q):

    sha_out = sha1.SHA1(m).finish()
    H_m = int(sha_out.hex(), 16)
    
    x_guess = ((((s*k) - H_m)) * invmod(r, q)) % q
    
    return(x_guess)