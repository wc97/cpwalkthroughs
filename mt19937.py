# -*- coding: utf-8 -*-
"""
Created on Thu Feb 27 18:10:04 2020

@author: willc
"""

cW = 32
cN = 624
cM = 397
cR = 31

cA = int('9908b0df', 16)
cU = 11
cD = int('ffffffff', 16) # 2**32-1 --> max int value.
cS = 7
cB = int('9d2c5680', 16)
cT = 15
cC = int('efc60000', 16)
cL = 18

cF = 1812433253

cMASK_LOWER_32 = (1 << cW) - 1   # 2**32 - 1
cLOWER_MASK   = (1 << cR) - 1   # 2**31 - 1
cUPPER_MASK   = (1 << cR)       # 2**31

def mt_reverse_temper(y):

    # Undo:  y ^= (y >> cL)
    y ^= (y >> cL) ^ (y >> (cL*2))

    # Undo:  y ^= ((y << cT) & cC)
    y ^= (y << cT) & cC

    # Undo:  y ^= ((y << cS) & cB)
    x = y
    for ii in range(4):
        x = (x << cS) & cB
        y ^= x

    # Undo:  y ^= ((y >> cU) & cD)
    y ^= ((y >> cU) ^ (y >> (cU * 2)))

    return(y & cD)

class mt19937:

    def __init__(self, seed):

        # initialize the MT state
        self.state = [0] * cN
        self.seed = seed

        self.index = cN
        self.state[0] = seed

        for ii in range(1, cN):

            #tmp = (cF * self.state[ii-1]) ^ ((self.state[ii-1] >> (cW-2)) + ii)
            tmp = cF * (self.state[ii-1] ^ (self.state[ii-1] >> (cW-2))) + ii
            self.state[ii] = tmp & cMASK_LOWER_32

    def extract_number(self):

        if self.index >= cN:

            if self.index > cN:

                raise(ValueError('Not seeded'))

            self.twist()

        y = self.state[self.index]
        y ^= ((y >> cU) & cD)
        y ^= ((y << cS) & cB)
        y ^= ((y << cT) & cC)
        y ^= (y >> cL)

        self.index += 1

        tmp = y & cMASK_LOWER_32
        return(tmp)

    def twist(self):

        for ii in range(cN):

            x = (self.state[ii] & cUPPER_MASK) + \
                (self.state[(ii+1) % cN] & cLOWER_MASK)

            xA = x >> 1

            if (x % 2) != 0:

                xA = xA ^ cA

            self.state[ii] = self.state[(ii + cM) % cN] ^ xA

        self.index = 0
