# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""

import math

from Crypto.Util import number
from Crypto.Random import random
import cryptopals as cp

from decimal import *

def remove_pkcs15_padding(byte_data, n):
    
    k = math.ceil(math.log2(n)) // 8
    
    if len(byte_data)==(k-1):        
        byte_data = b'\x00' + byte_data
    
    if not(len(byte_data) == k):
        return(False)

    if not(byte_data[1] == 0x02):
        return(False)
    
    data_idx = byte_data.find(b'\x00', 2) + 1   
    payload = byte_data[data_idx:]
    
    return(payload)
    
def validate_pkcs15_padding(byte_data, n):

    k = math.ceil(math.log2(n)) // 8
    
    if len(byte_data)==(k-1):        
        byte_data = b'\x00' + byte_data
    
    if not(len(byte_data) == k):
        return(False)

    if not(byte_data[1] == 0x02):
        return(False)
    
    data_idx = byte_data.find(b'\x00', 3) + 1
    
    return not(data_idx == 0)

def simple_validate_padding(byte_data, n):

    k = math.ceil(math.log2(n)) // 8
    
    if len(byte_data)==(k-1):        
        byte_data = b'\x00' + byte_data
    
    if not(len(byte_data) == k):
        return(False)

    if not(byte_data[1] == 0x02):
        return(False)

    return(True)

def pkcs15_pad(data, n):
    
    k = math.ceil(math.log2(n)) // 8
    data_len = len(data)
    ps_len = k - data_len - 3
    
    b00 = b'\x00'
    BT = b'\x02'
    PS = []
    
    for ii in range(ps_len):
        PS.append(random.randint(1, 255))
    
    EB = b00 + BT + bytes(PS) + b00 + data
    
    return(EB)

def bytes_to_bigint(byte_data):
    
    return(int(byte_data.hex(), 16))

def bigint_to_bytes(int_data):
    
    hex_data = hex(int_data)[2:]
    if len(hex_data) % 2:
        hex_data = '0' + hex_data
    return(bytes.fromhex(hex_data))

def challenge47_oracle(ciphertext):
    
    plaintext = int(pow(ciphertext, d, n))
    plaintext_hex = hex(plaintext)[2:]
    if (len(plaintext_hex) % 2):
        plaintext_hex = '0' + plaintext_hex
    plaintext_bytes = bytes.fromhex(plaintext_hex)
    
    return( simple_validate_padding(plaintext_bytes, n) )

def update_intervals(M_Last, s):
    
    M = []

    for interval in M_Last:

        last_a, last_b = interval[1], interval[2]
        r_min = math.ceil((last_a*s - 3*B + 1) / n)
        r_max = math.ceil((last_b*s - 2*B) / n)

        for r in range(r_min, r_max+1):
            
            new_a = int(max(last_a, math.ceil((2*B + r*n) / s) ))
            new_b = int(min(last_b, math.floor((3*B - 1 + r*n) / s) ))

            if new_b > new_a:
                
                if len(M) == 0:                
                    
                    M.append([r, new_a, new_b])
                    
                else:
                    
                    M_min = sorted(M, key=lambda x: x[1])[0][1]
                    M_max = sorted(M, key=lambda x: x[2])[-1][2]
                    
                    if new_b < M_min or new_a > M_max:
                    
                        M.append([r, new_a, new_b])
                        
                    else:
                        
                        for this_interval in M:
                            
                            this_min = this_interval[1]
                            this_max = this_interval[2]
                            if (new_a < this_min) and (new_b < this_max):
                                this_interval[1] = new_a
                            elif (new_a > this_min) and (new_b > this_max):
                                this_interval[2] = new_b
                    
    if M == []:
        return(M_Last)
        print('Houston, we have a problem')
    else:
        return(M)



valid_params = False
while not(valid_params):
    
    print('.', end='')
    p = number.getPrime(256 // 2)
    q = number.getPrime(256 // 2)

    n = (p * q)

    et = (p-1) * (q-1)
    e = 3

    d = cp.invmod(e, et)

    # Check parameters:
    PT = random.randint(0, 2**32-1)
    valid_params = (pow(pow(PT, e, n), d, n) == PT)

print(f"\nGenerated working parameters:\n")
print(f"e={e}\nd={d}\nn={n}")

# Set decimal precision to handle math  for this challenge...
getcontext().prec = int(math.log2(n))

m = bytes_to_bigint(pkcs15_pad(b'kick it, cc', n))
c = pow(m, e, n)
true_p = pow(c, d, n)


k = math.ceil(math.log2(n)) // 8
B = Decimal(2**(8*(k-2)))
s0 = math.ceil(n / (3*B))
n_queries = 0


print('Finding first s')
conforming = False
while not(conforming):
    
    c_ = c*(pow(s0, e, n)) % n
    conforming = challenge47_oracle(c_)
    n_queries += 1
    if not(conforming):
        s0 += 1   
        
s = s0

M = [[0, 2*B, 3*B - 1]]
#M = update_intervals(M, s)

a = Decimal(0)
b = Decimal(0)
r = Decimal(0)
nDec = Decimal(n)

done = False

while not(done):

    conforming = False
    #print(M)
    if len(M) > 1:
        
        # Step 2.b:  Searching with more than one interval left
        print('[2b]', end='')
        while not(conforming):
            #if s % 10000 == 0:
            #    print('X', end='')
            s += 1
            c_ = int(c*(pow(s, e, n)) % n)            
            conforming = challenge47_oracle(c_)
            n_queries += 1
            
    else: 
        
        # Step 2.c:  Searching with one interval left
        a, b = Decimal(M[0][1]), Decimal(M[0][2])
        r = math.ceil(2*((b*s - 2*B) / n)) 
                
        while not(conforming):
            
            s_min = math.ceil((2*B + r*n) / b) 
            s_max = math.ceil((3*B + r*n) / a) 
            
            s = s_min
            
            while not(conforming) and (s <= s_max):

                c_ = int(c*(pow(s, e, n)) % n)
                conforming = challenge47_oracle(c_)
                n_queries += 1
                if not(conforming):
                    s += 1
                
            r += 1
            #print('.', end='')
            #print(f'[r={r}]', end='')
            
    M = update_intervals(M, s)
    b = math.log2(M[0][2] - M[0][1])
    print(int(b), end=';')
    if int(b) == 0:
        print(f'\n{M[0][2] - M[0][1]}')
    
    #if (b < 3) and (n_queries % 100000 == 0):
        #pdb.set_trace()
    
    if (len(M) == 1) and (M[0][1] == M[0][2]): 
        done = True
        
recovered_msg = remove_pkcs15_padding(bigint_to_bytes(M[0][1]), n)
print(recovered_msg)