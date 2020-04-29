# -*- coding: utf-8 -*-
"""
Created on Wed Apr 29 08:43:54 2020

@author: cobb
"""
import hashlib
import my_md4 as md4
from Crypto.Random import random

md4.run_RFC_tests()
md4.run_Wang_examples()

# Try to find an MD4 collision on random inputs -- probability is 2**-25 using 
# just the round 1 changes.

do_padding = False
ctr = 0
max_tries = 2**27
fixA5 = True
fixD5 = True
    
print(f"Searching for MD4 Collisions.  Max Attempts = {max_tries}")
#display(progress)

collision_found = False
while not(collision_found) and ctr < max_tries:

    original_msg = random.Random.get_random_bytes(64)
    msg = original_msg
    
    # First, do corrections to make the message "weak"
    msg = md4.Wang_SSM_New(msg, do_padding)
    if fixA5:
        msg = md4.Wang_fixA5_2(msg, do_padding)    
    
    if fixD5:
        msg = md4.Wang_fixD5(msg, do_padding)
    
    # Then, apply the differential
    msg_ = md4.Wang_Msg_Differential(msg) 
    
    # Check for a collision between the two messages.
    a = hashlib.new('md4', msg_).digest()
    b = hashlib.new('md4', msg).digest()
    #if md4.MD4(msg_, do_padding) == md4.MD4(msg, do_padding):
    if a==b:
        collision_found = True
        
    ctr += 1
    if ctr % 2**12 == 0:
        print('.', end='')
        
    if ctr % 2**16 == 0:
        print()
        print(ctr)
        
if ctr == max_tries:
    print('Boooo')
else:
    print('*************************************************')
    print('Collision found!')
    print()
    print(f'Original Message = {original_msg.hex()}')
    print(f'M = {msg.hex()}')
    print(f'M = {msg_.hex()}')
    print(f'Hash = {md4.MD4(msg).hex()}')
    print(f'Number of Attempts:  {ctr}')

