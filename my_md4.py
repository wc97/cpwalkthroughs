# import hashlib
#import cryptopals as cp

MGK_1 = 0x5a827999
MGK_2 = 0x6ed9eba1

W = [ 
        [0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15], 
        [0,  4,  8, 12,  1,  5,  9, 13,  2,  6, 10, 14,  3,  7, 11, 15],
        [0,  8,  4, 12,  2, 10,  6, 14,  1,  9,  5, 13,  3, 11,  7, 15] 
    ]   

S = [ 
        [3, 7, 11, 19],
        [3, 5,  9, 13],
        [3, 9, 11, 15]
    ]    

# Setup matrix containing Wang's corrections
# Each row is a step in the MD4 algorithm.
# Each column is a bit of the value being computed during that 
# step, ordered from LSB to MSB (left to right).

#                           Bit #'ing
#              00000000001111111111222222222233
#              01234567890123456789012345678901 
Wang_Rules = ['......=.........................',
             '......0=..=.....................',
             '......11..0..............=......',
             '......10..0..............0......',
             '.......1..1..=...........0......',
             '.............0....====...1......',
             '............=0=...0010..........',
             '............110.=.0000..........',
             '............111.0.0001=..=......',
             '............111.0..0110..1...=..',
             '................1..0000..0...1.=',
             '...................011=..1...0.0',
             '......................0..0=.=1.0',
             '......................0..01.10.1',
             '..................=...1..10.00..',
             '..................0......11.10.=']


def bitget(x, n):
    """Return bit #n of x"""
    return (x >> n) & 1

def bit_in_place(x, n):
    """Return bit #n of x in its original bit position"""
    return (x & 2**n)

def bitset(x, n, bv):
    """Set bit #n of x to bv"""
    if bv==1:
        x |= 2**n
    else:
        x ^= bit_in_place(x, n)
    return(x)

def lrot_32(n, d):
    """Circular rotate left.  Python only natively supports non-circular shift."""
    return ( (n << d) | (n >> (32 - d)) )

def rrot_32(n, d):
    """Circular rotate right.  Python only natively supports non-circular shift."""
    return ( (n << (32 - d)) | (n >> d) )

def byte_swap(data, word_size):
    """ 
    Byte-swap's a byte string of words.  
    Specify word-length in bytes.
    """
    
    bs_data = [0]*len(data)
    for ii in range(0, len(data), word_size):
        bs_data[ii:ii+word_size] = data[ii:ii+4][::-1]
    return(bytes(bs_data))

def F(X, Y, Z):         
    return (X & Y) | (~X & Z)

def G(X, Y, Z):
    return (X & Y) | (X & Z) | (Y & Z)

def H(X, Y, Z):
    return (X ^ Y ^ Z)

def phi(j, a, b, c, d, w, s):      
        
    if j == 0:            
        x = lrot_32(((a + F(b, c, d) + w) % 2**32), s)        
    elif j ==  1:            
        x = lrot_32(((a + G(b, c, d) + w + MGK_1) % 2**32), s)            
    elif j == 2:            
        x = lrot_32(((a + H(b, c, d) + w + MGK_2) % 2**32), s)                 
    return(x % 2**32)

def un_phi(j, a, b, c, d, T, s):
    
    if j==0:        
        w = (rrot_32(T, s) - a - F(b, c, d)) 
    elif j == 1:    
        w = (rrot_32(T, s) - a - G(b, c, d) - MGK_1) 
    elif j == 2:
        w = (rrot_32(T, s) - a - H(b, c, d) - MGK_2)
        
    return (w % 2**32)

def apply_corrections(var1, var2, corrections):
    
    #pdb.set_trace()
    for c_idx in range(32):
        if corrections[c_idx] != '.':
            if corrections[c_idx] == '0':
                var1 = bitset(var1, c_idx, 0)
            elif corrections[c_idx] == '1':
                var1 = bitset(var1, c_idx, 1)
            elif corrections[c_idx] == '=':
                var1 = bitset(var1, c_idx, bitget(var2, c_idx))
            else:
                raise(ValueError('Invalid Wang Rule'))
    return(var1)

def MD4_get_words(data, endianness='little'):
    
    M = []
    for ii in range(0, len(data), 4):
        word = int.from_bytes(data[ii:ii+4], byteorder=endianness, signed=False)
        M.append(word)
        
    return(M)

def MD4_get_data(M, endianness='little'):
    
    data = b''
    for ii in range(16):
        M[ii] = M[ii] % 2**32
        data += M[ii].to_bytes(4, endianness)
        
    return(data)

def MD4_pad_data(data, endianness='little'):
    
    if isinstance(data, str):
        data = data.encode()
    
    # Step 1:  Append padding bits.  Single 1-bit + 0-bits so that
    #          length of message is congruent to 448 mod 512.
    #          I'll assume we're always passed a string of bytes.
    
    bit_length = len(data)*8
    
    # append 1-bit = 0x80 
    data += b'\x80' # Hex 0x80 = 0b10000000
    
    data_len = len(data) % 64
    padding_len = (56 - data_len) % 64
    
    data += b'\x00'*padding_len
    
    # Step 2:  Append length.  64-bit representation before padding.
    
    data += bit_length.to_bytes(8, endianness, signed=False)
    
    return(data)

def ABCD_to_M(A,B,C,D):

    # Now back out the modified M
    M = [0]*16
    M[0] = (rrot_32(A[1], 3)  - A[0] - F(B[0], C[0], D[0])) % 2**32
    M[1] = (rrot_32(D[1], 7)  - D[0] - F(A[1], B[0], C[0])) % 2**32
    M[2] = (rrot_32(C[1], 11) - C[0] - F(D[1], A[1], B[0])) % 2**32
    M[3] = (rrot_32(B[1], 19) - B[0] - F(C[1], D[1], A[1])) % 2**32

    M[4] = (rrot_32(A[2], 3)  - A[1] - F(B[1], C[1], D[1])) % 2**32
    M[5] = (rrot_32(D[2], 7)  - D[1] - F(A[2], B[1], C[1])) % 2**32
    M[6] = (rrot_32(C[2], 11) - C[1] - F(D[2], A[2], B[1])) % 2**32
    M[7] = (rrot_32(B[2], 19) - B[1] - F(C[2], D[2], A[2])) % 2**32

    M[8] = (rrot_32(A[3], 3)   - A[2] - F(B[2], C[2], D[2])) % 2**32
    M[9] = (rrot_32(D[3], 7)   - D[2] - F(A[3], B[2], C[2])) % 2**32
    M[10] = (rrot_32(C[3], 11) - C[2] - F(D[3], A[3], B[2])) % 2**32
    M[11] = (rrot_32(B[3], 19) - B[2] - F(C[3], D[3], A[3])) % 2**32

    M[12] = (rrot_32(A[4], 3)  - A[3] - F(B[3], C[3], D[3])) % 2**32
    M[13] = (rrot_32(D[4], 7)  - D[3] - F(A[4], B[3], C[3])) % 2**32
    M[14] = (rrot_32(C[4], 11) - C[3] - F(D[4], A[4], B[3])) % 2**32
    M[15] = (rrot_32(B[4], 19) - B[3] - F(C[4], D[4], A[4])) % 2**32

    return(M)

def MD4_get_IVs(M):

    
    # Step 4:  Process Message in blocks of 16 32-bit words (512 bits ea)
    
    # Run the compression algorithm.  Loop for each block of 512 bits until
    # full message is consumed.
    
    W = [ [0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15], 
          [0,  4,  8, 12,  1,  5,  9, 13,  2,  6, 10, 14,  3,  7, 11, 15],
          [0,  8,  4, 12,  2, 10,  6, 14,  1,  9,  5, 13,  3, 11,  7, 15] ]   
    
    S = [ [3, 7, 11, 19],
          [3, 5,  9, 13],
          [3, 9, 11, 15]]    

    A, B, C, D = [0x67452301], [0xefcdab89], [0x98badcfe], [0x10325476]
    
    N = len(M)//16

    for kk in range(N):
        
        AA, BB, CC, DD = A[-1], B[-1], C[-1], D[-1]
        X = M[16*kk:16*(kk+1)]
        
        for jj in range(3):        
            for ii in range(4):
                A.append(phi(jj, A[-1], B[-1], C[-1], D[-1], X[W[jj][4*ii+0]], S[jj][0]))
                D.append(phi(jj, D[-1], A[-1], B[-1], C[-1], X[W[jj][4*ii+1]], S[jj][1]))
                C.append(phi(jj, C[-1], D[-1], A[-1], B[-1], X[W[jj][4*ii+2]], S[jj][2]))
                B.append(phi(jj, B[-1], C[-1], D[-1], A[-1], X[W[jj][4*ii+3]], S[jj][3]))
     
        A.append((A[-1] + AA) % 2**32)
        B.append((B[-1] + BB) % 2**32)
        C.append((C[-1] + CC) % 2**32)
        D.append((D[-1] + DD) % 2**32)

    return(A, B, C, D)

def MD4_get_IVs_UR(M):
    
    N = len(M) // 16
    L = 13*N+1
    A,B,C,D = [0]*L, [0]*L, [0]*L, [0]*L
    MGK_1, MKG_2 = 0x5a827999, 0x6ed9eba1

    A[0] = 0x67452301 
    D[0] = 0x10325476
    C[0] = 0x98badcfe
    B[0] = 0xefcdab89
    
    # Round 0, j=0, i = [0:3]
    A[1] = lrot_32( (A[0] + F(B[0], C[0], D[0]) + M[0]) % 2**32, 3)
    D[1] = lrot_32( (D[0] + F(A[1], B[0], C[0]) + M[1]) % 2**32, 7)
    C[1] = lrot_32( (C[0] + F(D[1], A[1], B[0]) + M[2]) % 2**32, 11)
    B[1] = lrot_32( (B[0] + F(C[1], D[1], A[1]) + M[3]) % 2**32, 19)
    
    A[2] = lrot_32( (A[1] + F(B[1], C[1], D[1]) + M[4]) % 2**32, 3)
    D[2] = lrot_32( (D[1] + F(A[2], B[1], C[1]) + M[5]) % 2**32, 7)
    C[2] = lrot_32( (C[1] + F(D[2], A[2], B[1]) + M[6]) % 2**32, 11)
    B[2] = lrot_32( (B[1] + F(C[2], D[2], A[2]) + M[7]) % 2**32, 19) 
    
    A[3] = lrot_32( (A[2] + F(B[2], C[2], D[2]) + M[8]) % 2**32, 3)
    D[3] = lrot_32( (D[2] + F(A[3], B[2], C[2]) + M[9]) % 2**32, 7)
    C[3] = lrot_32( (C[2] + F(D[3], A[3], B[2]) + M[10]) % 2**32, 11)
    B[3] = lrot_32( (B[2] + F(C[3], D[3], A[3]) + M[11]) % 2**32, 19)
    
    A[4] = lrot_32( (A[3] + F(B[3], C[3], D[3]) + M[12]) % 2**32, 3)
    D[4] = lrot_32( (D[3] + F(A[4], B[3], C[3]) + M[13]) % 2**32, 7)
    C[4] = lrot_32( (C[3] + F(D[4], A[4], B[3]) + M[14]) % 2**32, 11)
    B[4] = lrot_32( (B[3] + F(C[4], D[4], A[4]) + M[15]) % 2**32, 19)    
    
    # j = 1
    # phi = lrot_32(((a + G(b, c, d) + w + MGK_1) % 2**32), s)  
    A[5] = lrot_32( (A[4] + G(B[4], C[4], D[4]) + M[0] + MGK_1) % 2**32, 3)
    D[5] = lrot_32( (D[4] + G(A[5], B[4], C[4]) + M[4] + MGK_1) % 2**32, 5)
    C[5] = lrot_32( (C[4] + G(D[5], A[5], B[4]) + M[8] + MGK_1) % 2**32, 9)
    B[5] = lrot_32( (B[4] + G(C[5], D[5], A[5]) + M[12] + MGK_1) % 2**32, 13)
   
    A[6] = lrot_32( (A[5] + G(B[5], C[5], D[5]) + M[1] + MGK_1) % 2**32, 3)
    D[6] = lrot_32( (D[5] + G(A[6], B[5], C[5]) + M[5] + MGK_1) % 2**32, 5)
    C[6] = lrot_32( (C[5] + G(D[6], A[6], B[5]) + M[9] + MGK_1) % 2**32, 9)
    B[6] = lrot_32( (B[5] + G(C[6], D[6], A[6]) + M[13] + MGK_1) % 2**32, 13) 
    
    A[7] = lrot_32( (A[6] + G(B[6], C[6], D[6]) + M[2] + MGK_1) % 2**32, 3)
    D[7] = lrot_32( (D[6] + G(A[7], B[6], C[6]) + M[6] + MGK_1) % 2**32, 5)
    C[7] = lrot_32( (C[6] + G(D[7], A[7], B[6]) + M[10] + MGK_1) % 2**32, 9)
    B[7] = lrot_32( (B[6] + G(C[7], D[7], A[7]) + M[14] + MGK_1) % 2**32, 13)
    
    A[8] = lrot_32( (A[7] + G(B[7], C[7], D[7]) + M[3] + MGK_1) % 2**32, 3)
    D[8] = lrot_32( (D[7] + G(A[8], B[7], C[7]) + M[7] + MGK_1) % 2**32, 5)
    C[8] = lrot_32( (C[7] + G(D[8], A[8], B[7]) + M[11] + MGK_1) % 2**32, 9)
    B[8] = lrot_32( (B[7] + G(C[8], D[8], A[8]) + M[15] + MGK_1) % 2**32, 13)      
    
    # j = 2
    # phi = lrot_32(((a + H(b, c, d) + w + MGK_2) % 2**32), s)  
    A[9] = lrot_32( (A[8] + H(B[8], C[8], D[8]) + M[0] + MGK_2) % 2**32, 3)
    D[9] = lrot_32( (D[8] + H(A[9], B[8], C[8]) + M[8] + MGK_2) % 2**32, 9)
    C[9] = lrot_32( (C[8] + H(D[9], A[9], B[8]) + M[4] + MGK_2) % 2**32, 11)
    B[9] = lrot_32( (B[8] + H(C[9], D[9], A[9]) + M[12] + MGK_2) % 2**32, 15)
   
    A[10] = lrot_32( (A[9] + H(B[9], C[9], D[9]) + M[2] + MGK_1) % 2**32, 3)
    D[10] = lrot_32( (D[9] + H(A[10], B[9], C[9]) + M[10] + MGK_1) % 2**32, 9)
    C[10] = lrot_32( (C[9] + H(D[10], A[10], B[9]) + M[6] + MGK_1) % 2**32, 11)
    B[10] = lrot_32( (B[9] + H(C[10], D[10], A[10]) + M[14] + MGK_1) % 2**32, 15) 
    
    A[11] = lrot_32( (A[10] + H(B[10], C[10], D[10]) + M[1] + MGK_1) % 2**32, 3)
    D[11] = lrot_32( (D[10] + H(A[11], B[10], C[10]) + M[9] + MGK_1) % 2**32, 9)
    C[11] = lrot_32( (C[10] + H(D[11], A[11], B[10]) + M[5] + MGK_1) % 2**32, 11)
    B[11] = lrot_32( (B[10] + H(C[11], D[11], A[11]) + M[13] + MGK_1) % 2**32, 15)
    
    A[12] = lrot_32( (A[11] + H(B[11], C[11], D[11]) + M[3] + MGK_1) % 2**32, 3)
    D[12] = lrot_32( (D[11] + H(A[12], B[11], C[11]) + M[11] + MGK_1) % 2**32, 9)
    C[12] = lrot_32( (C[11] + H(D[12], A[12], B[11]) + M[7] + MGK_1) % 2**32, 11)
    B[12] = lrot_32( (B[11] + H(C[12], D[12], A[12]) + M[15] + MGK_1) % 2**32, 15) 
    
    A[13] = (A[12] + A[0]) % 2**32
    D[13] = (D[12] + D[0]) % 2**32
    C[13] = (C[12] + C[0]) % 2**32
    B[13] = (B[12] + B[0]) % 2**32
    
def MD4(data, do_padding = True, endianness = 'little'):
    
    """ 
    Modified my MD4 implementation to better track with the notation used
    in Wang's paper -- and to keep intermediate results for all loop iterations
    within a round.  Could also modify to retain intermediates across rounds if
    needed.
    """
    if do_padding:
        M = MD4_get_words(MD4_pad_data(data), endianness)
    else:
        if len(data) < 64:
            data += b'\x00'*(64-len(data))
        M = MD4_get_words(data, endianness)
        
    A, B, C, D = MD4_get_IVs(M)           
    #pdb.set_trace()
    digest = A[-1].to_bytes(4, endianness) + \
             B[-1].to_bytes(4, endianness) + \
             C[-1].to_bytes(4, endianness) + \
             D[-1].to_bytes(4, endianness)
   
    return(digest)


def Wang_Msg_Differential(data, endianness='little'):
    
    M = MD4_get_words(data, endianness)
    M[1] = (M[1] + 2**31) % 2**32
    M[2] = (M[2] + (2**31 - 2**28)) % 2**32
    M[12] = (M[12] - 2**16) % 2**32
    
    return(MD4_get_data(M, endianness))


def check_conditions(A,B,C,D):
    
    assert(bitget(A[1], 6) == bitget(B[0], 6))
    assert(bitget(D[1], 6) == 0)
    assert(bitget(D[1], 7) == bitget(A[1], 7))
    assert(bitget(D[1], 10) == bitget(A[1], 10))
    assert(bitget(C[1], 6) == 1)
    assert(bitget(C[1], 7) == 1)
    assert(bitget(C[1], 10) == 0)
    assert(bitget(C[1], 25) == bitget(D[1], 25))
    assert(bitget(B[1], 6) == 1)
    assert(bitget(B[1], 7) == 0)
    assert(bitget(B[1], 10) == 0)
    assert(bitget(B[1], 25) == 0)
    assert(bitget(A[2], 7) == 1)
    assert(bitget(A[2], 10) == 1)
    assert(bitget(A[2], 13) == bitget(B[1], 13))
    assert(bitget(A[2], 25) == 0)
    assert(bitget(D[2], 13) == 0)
    assert(bitget(D[2], 18) == bitget(A[2], 18))
    assert(bitget(D[2], 19) == bitget(A[2], 19))
    assert(bitget(D[2], 20) == bitget(A[2], 20))
    assert(bitget(D[2], 21) == bitget(A[2], 21))
    assert(bitget(D[2], 25) == 1)
    assert(bitget(C[2], 12) == bitget(D[2], 12))
    assert(bitget(C[2], 13) == 0)
    assert(bitget(C[2], 14) == bitget(D[2], 14))
    assert(bitget(C[2], 18) == 0)
    assert(bitget(C[2], 19) == 0)
    assert(bitget(C[2], 20) == 1)
    assert(bitget(C[2], 21) == 0)
    assert(bitget(B[2], 12) == 1)
    assert(bitget(B[2], 13) == 1)
    assert(bitget(B[2], 14) == 0)
    assert(bitget(B[2], 16) == bitget(C[2], 16))
    assert(bitget(B[2], 18) == 0)
    assert(bitget(B[2], 19) == 0)
    assert(bitget(B[2], 20) == 0)
    assert(bitget(B[2], 21) == 0)
    assert(bitget(A[3], 12) == 1)
    assert(bitget(A[3], 13) == 1)
    assert(bitget(A[3], 14) == 1)
    assert(bitget(A[3], 16) == 0)
    assert(bitget(A[3], 18) == 0)
    assert(bitget(A[3], 19) == 0)
    assert(bitget(A[3], 20) == 0)
    assert(bitget(A[3], 21) == 1)
    assert(bitget(A[3], 22) == bitget(B[2], 22))
    assert(bitget(A[3], 25) == bitget(B[2], 25))
    assert(bitget(D[3], 12) == 1)
    assert(bitget(D[3], 13) == 1)
    assert(bitget(D[3], 14) == 1)
    assert(bitget(D[3], 16) == 0)
    assert(bitget(D[3], 19) == 0)
    assert(bitget(D[3], 20) == 1)
    assert(bitget(D[3], 21) == 1)
    assert(bitget(D[3], 22) == 0)
    assert(bitget(D[3], 25) == 1)
    assert(bitget(D[3], 29) == bitget(A[3], 29))
    assert(bitget(C[3], 16) == 1)
    assert(bitget(C[3], 19) == 0)
    assert(bitget(C[3], 20) == 0)
    assert(bitget(C[3], 21) == 0)
    assert(bitget(C[3], 22) == 0)
    assert(bitget(C[3], 25) == 0)
    assert(bitget(C[3], 29) == 1)
    assert(bitget(C[3], 31) == bitget(D[3], 31))
    assert(bitget(B[3], 19) == 0)
    assert(bitget(B[3], 20) == 1)
    assert(bitget(B[3], 21) == 1)
    assert(bitget(B[3], 22) == bitget(C[3], 22))
    assert(bitget(B[3], 25) == 1)
    assert(bitget(B[3], 29) == 0)
    assert(bitget(B[3], 31) == 0)
    assert(bitget(A[4], 22) == 0)
    assert(bitget(A[4], 25) == 0)
    assert(bitget(A[4], 26) == bitget(B[3], 26))
    assert(bitget(A[4], 28) == bitget(B[3], 28))
    assert(bitget(A[4], 29) == 1)
    assert(bitget(A[4], 31) == 0)
    assert(bitget(D[4], 22) == 0)
    assert(bitget(D[4], 25) == 0)
    assert(bitget(D[4], 26) == 1)
    assert(bitget(D[4], 28) == 1)
    assert(bitget(D[4], 29) == 0)
    assert(bitget(D[4], 31) == 1)
    assert(bitget(C[4], 18) == bitget(D[4], 18))
    assert(bitget(C[4], 22) == 1)
    assert(bitget(C[4], 25) == 1)
    assert(bitget(C[4], 26) == 0)
    assert(bitget(C[4], 28) == 0)
    assert(bitget(C[4], 29) == 0)
    assert(bitget(B[4], 18) == 0)
    assert(bitget(B[4], 25) == 1)
    assert(bitget(B[4], 26) == 1)
    assert(bitget(B[4], 28) == 1)
    assert(bitget(B[4], 29) == 0)
    assert(bitget(B[4], 31) == bitget(C[4], 31))
    
    
def Wang_SSM(data, do_padding = False, endianness='little'):
    
    """ 
    Implements the single step modification from Wang's paper.
    """
    
    if do_padding:
        
        M = MD4_get_words(MD4_pad_data(data), endianness)
        
    else:
        
        if len(data) < 64:
            data += b'\x00'*(64-len(data))
            
        M = MD4_get_words(data, endianness) 
    
    A, B, C, D = MD4_get_IVs(M)   
    # Modify the message to meet several of the constraints in Table 6
    # All bit #ing has been converted from base 1 to base 0
    
    A[1] = bitset(A[1], 6, bitget(B[0], 6))
    
    D[1] = bitset(D[1], 6, 0)
    D[1] = bitset(D[1], 7, bitget(A[1], 7))
    D[1] = bitset(D[1], 10, bitget(A[1], 10))
    C[1] = bitset(C[1], 6, 1)
    C[1] = bitset(C[1], 7, 1)
    C[1] = bitset(C[1], 10, 0)
    C[1] = bitset(C[1], 25, bitget(D[1], 25))
    B[1] = bitset(B[1], 6, 1)
    B[1] = bitset(B[1], 7, 0)
    B[1] = bitset(B[1], 10, 0)
    B[1] = bitset(B[1], 25, 0)
    A[2] = bitset(A[2], 7, 1)
    A[2] = bitset(A[2], 10, 1)
    A[2] = bitset(A[2], 13, bitget(B[1], 13))
    A[2] = bitset(A[2], 25, 0) 
    D[2] = bitset(D[2], 13, 0)
    D[2] = bitset(D[2], 18, bitget(A[2], 18))
    D[2] = bitset(D[2], 19, bitget(A[2], 19))
    D[2] = bitset(D[2], 20, bitget(A[2], 20))
    D[2] = bitset(D[2], 21, bitget(A[2], 21))
    D[2] = bitset(D[2], 25, 1)   
    C[2] = bitset(C[2], 12, bitget(D[2], 12))
    C[2] = bitset(C[2], 13, 0)
    C[2] = bitset(C[2], 14, bitget(D[2], 14))
    C[2] = bitset(C[2], 18, 0)
    C[2] = bitset(C[2], 19, 0)
    C[2] = bitset(C[2], 20, 1)
    C[2] = bitset(C[2], 21, 0)
    B[2] = bitset(B[2], 12, 1)
    B[2] = bitset(B[2], 13, 1)
    B[2] = bitset(B[2], 14, 0)
    B[2] = bitset(B[2], 16, bitget(C[2], 16))
    B[2] = bitset(B[2], 18, 0)
    B[2] = bitset(B[2], 19, 0)
    B[2] = bitset(B[2], 20, 0)
    B[2] = bitset(B[2], 21, 0)
    A[3] = bitset(A[3], 12, 1)
    A[3] = bitset(A[3], 13, 1)
    A[3] = bitset(A[3], 14, 1)
    A[3] = bitset(A[3], 16, 0)
    A[3] = bitset(A[3], 18, 0)
    A[3] = bitset(A[3], 19, 0)
    A[3] = bitset(A[3], 20, 0)
    A[3] = bitset(A[3], 21, 1)
    A[3] = bitset(A[3], 22, bitget(B[2], 22))
    A[3] = bitset(A[3], 25, bitget(B[2], 25))      
    D[3] = bitset(D[3], 12, 1)
    D[3] = bitset(D[3], 13, 1)
    D[3] = bitset(D[3], 14, 1)
    D[3] = bitset(D[3], 16, 0)
    D[3] = bitset(D[3], 19, 0)
    D[3] = bitset(D[3], 20, 1)
    D[3] = bitset(D[3], 21, 1)
    D[3] = bitset(D[3], 22, 0)
    D[3] = bitset(D[3], 25, 1)
    D[3] = bitset(D[3], 29, bitget(A[3], 29))     
    C[3] = bitset(C[3], 16, 1)
    C[3] = bitset(C[3], 19, 0)
    C[3] = bitset(C[3], 20, 0)
    C[3] = bitset(C[3], 21, 0)
    C[3] = bitset(C[3], 22, 0)
    C[3] = bitset(C[3], 25, 0)
    C[3] = bitset(C[3], 29, 1)
    C[3] = bitset(C[3], 31, bitget(D[3], 31))
    B[3] = bitset(B[3], 19, 0)
    B[3] = bitset(B[3], 20, 1)
    B[3] = bitset(B[3], 21, 1)
    B[3] = bitset(B[3], 22, bitget(C[3], 22))
    B[3] = bitset(B[3], 25, 1)
    B[3] = bitset(B[3], 29, 0)
    B[3] = bitset(B[3], 31, 0)   
    A[4] = bitset(A[4], 22, 0)
    A[4] = bitset(A[4], 25, 0)
    A[4] = bitset(A[4], 26, bitget(B[3], 26))
    A[4] = bitset(A[4], 28, bitget(B[3], 28))
    A[4] = bitset(A[4], 29, 1)
    A[4] = bitset(A[4], 31, 0)  
    D[4] = bitset(D[4], 22, 0)
    D[4] = bitset(D[4], 25, 0)
    D[4] = bitset(D[4], 26, 1)
    D[4] = bitset(D[4], 28, 1)
    D[4] = bitset(D[4], 29, 0)
    D[4] = bitset(D[4], 31, 1)    
    C[4] = bitset(C[4], 18, bitget(D[4], 18))
    C[4] = bitset(C[4], 22, 1)
    C[4] = bitset(C[4], 25, 1)
    C[4] = bitset(C[4], 26, 0)
    C[4] = bitset(C[4], 28, 0)
    C[4] = bitset(C[4], 29, 0) 
    B[4] = bitset(B[4], 18, 0)
    B[4] = bitset(B[4], 25, 1)
    B[4] = bitset(B[4], 26, 1)
    B[4] = bitset(B[4], 28, 1)
    B[4] = bitset(B[4], 29, 0)
    # Extra constraint
    B[4] = bitset(B[4], 31, bitget(C[4], 31))
    
    M = ABCD_to_M(A,B,C,D)
    new_data = MD4_get_data(M, endianness)
    M = MD4_get_words(new_data)
    A, B, C, D = MD4_get_IVs(M) 
    check_conditions(A, B, C, D)
  
    return(new_data)


def Wang_SSM_New(data, do_padding = False, endianness='little'):
    
    """ 
    Implements the single step modification from Wang's paper.
    """    
    
    if do_padding:        
        M = MD4_get_words(MD4_pad_data(data), endianness)        
    else:        
        if len(data) < 64:
            data += b'\x00'*(64-len(data))            
        M = MD4_get_words(data, endianness) 

    A, B, C, D = MD4_get_IVs(M)
    
    jj = 0 # Constant...we're just doing the 1st round corrections.
    for ii in range(4):
        
        corrections = Wang_Rules[4*ii]
        A[ii+1] = phi(jj, A[ii], B[ii], C[ii], D[ii], M[W[jj][4*ii+0]], S[jj][0])
        A[ii+1] = apply_corrections(A[ii+1], B[ii], corrections)
        M[W[jj][4*ii+0]] = un_phi(jj, A[ii], B[ii], C[ii], D[ii], A[ii+1], S[jj][0])
        
        corrections = Wang_Rules[4*ii+1]
        D[ii+1] = phi(jj, D[ii], A[ii+1], B[ii], C[ii], M[W[jj][4*ii+1]], S[jj][1])
        D[ii+1] = apply_corrections(D[ii+1], A[ii+1], corrections)
        M[W[jj][4*ii+1]] = un_phi(jj, D[ii], A[ii+1], B[ii], C[ii], D[ii+1], S[jj][1])
        
        corrections = Wang_Rules[4*ii+2]      
        C[ii+1] = phi(jj, C[ii], D[ii+1], A[ii+1], B[ii], M[W[jj][4*ii+2]], S[jj][2])
        C[ii+1] = apply_corrections(C[ii+1], D[ii+1], corrections)
        M[W[jj][4*ii+2]] = un_phi(jj, C[ii], D[ii+1], A[ii+1], B[ii], C[ii+1], S[jj][2])
        
        corrections = Wang_Rules[4*ii+3]
        B[ii+1] = phi(jj, B[ii], C[ii+1],   D[ii+1],   A[ii+1],   M[W[jj][4*ii+3]], S[jj][3])
        B[ii+1] = apply_corrections(B[ii+1], C[ii+1], corrections)
        M[W[jj][4*ii+3]] = un_phi(jj, B[ii], C[ii+1],   D[ii+1],   A[ii+1], B[ii+1], S[jj][3])
    
    new_data = MD4_get_data(M, endianness)
    
    return(new_data)

def Wang_fixA5(data, do_padding=True, endianness='little'):
    
    """ 
    Implement Table 1 changes modify M for A[5] corrections.
    """
    if do_padding:
        M = MD4_get_words(MD4_pad_data(data, endianness))
    else:
        if len(data) < 64:
            data += b'\x00'*(64-len(data))
        M = MD4_get_words(data, endianness) 
        
    for kk in [18, 25, 26, 28, 31]:

        A, B, C, D = MD4_get_IVs(M)  
        
        # Assume bits match...
        direction = 0
        
        if kk==18:
            direction = bitget(C[4], 18) - bitget(A[5], 18) 
        elif kk == 25:
            if bitget(A[5], 25) == 0:
                direction = 1
        elif kk == 26:
            if bitget(A[5], 26) == 1:
                direction = -1
        elif kk == 28:
            if bitget(A[5], 28) == 0:
                direction = 1
        elif kk == 31:
            if bitget(A[5], 31) == 0:
                direction = 1

        # Now back out the modified M
        if direction == 1:
            
            A[1] = bitset(A[1], kk, 1)
            M[0] = (M[0] + 2**(kk+1-4)) % 2**32
            M[1] = rrot_32(D[1],  7) - D[0] - F(A[1], B[0], C[0]) % 2**32
            M[2] = rrot_32(C[1], 11) - C[0] - F(D[1], A[1], B[0]) % 2**32
            M[3] = rrot_32(B[1], 19) - B[0] - F(C[1], D[1], A[1]) % 2**32
            M[4] = rrot_32(A[2],  3) - A[1] - F(B[1], C[1], D[1]) % 2**32
        elif direction == -1:
            A[1] = bitset(A[1], kk, 0)
            M[0] = (M[0] - 2**(kk+1-4)) % 2**32
            M[1] = rrot_32(D[1],  7) - D[0] - F(A[1], B[0], C[0]) % 2**32
            M[2] = rrot_32(C[1], 11) - C[0] - F(D[1], A[1], B[0]) % 2**32
            M[3] = rrot_32(B[1], 19) - B[0] - F(C[1], D[1], A[1]) % 2**32
            M[4] = rrot_32(A[2],  3) - A[1] - F(B[1], C[1], D[1]) % 2**32
        
    # Check constraints...a5;19 = c4;19, a5;26 = 1, a5;27 = 0, a5;29 = 1, a5;32 = 1
    A,B,C,D = MD4_get_IVs(M)
    assert(bitget(A[5], 18) == bitget(C[4], 18))
    assert(bitget(A[5], 25) == 1)
    assert(bitget(A[5], 26) == 0)
    assert(bitget(A[5], 28) == 1)    
    assert(bitget(A[5], 31) == 1)
    return(MD4_get_data(M, endianness))

def Wang_fixA5_2(data, do_padding=True, endianness='little'):
    
    """ 
    Implement Table 1 changes modify M for A[5] corrections.
    """
    if do_padding:
        M = MD4_get_words(MD4_pad_data(data, endianness))
    else:
        if len(data) < 64:
            data += b'\x00'*(64-len(data))
        M = MD4_get_words(data, endianness) 
        
    A, B, C, D = MD4_get_IVs(M)  
        
    A[5] = bitset(A[5], 18, bitget(C[4], 18))
    A[5] = bitset(A[5], 25, 1)
    A[5] = bitset(A[5], 26, 0)
    A[5] = bitset(A[5], 28, 1)
    A[5] = bitset(A[5], 31, 1)
    
    M[0] = rrot_32(A[5], 3) - A[4] - G(B[4], C[4], D[4]) - MGK_1
    
    A[1] = lrot_32( (A[0] + F(B[0], C[0], D[0]) + M[0]) % 2**32, 3)
    
    M[1] = rrot_32(D[1],  7) - D[0] - F(A[1], B[0], C[0]) % 2**32
    M[2] = rrot_32(C[1], 11) - C[0] - F(D[1], A[1], B[0]) % 2**32
    M[3] = rrot_32(B[1], 19) - B[0] - F(C[1], D[1], A[1]) % 2**32
    M[4] = rrot_32(A[2],  3) - A[1] - F(B[1], C[1], D[1]) % 2**32
        
    # Check constraints...a5;19 = c4;19, a5;26 = 1, a5;27 = 0, a5;29 = 1, a5;32 = 1
    #A,B,C,D = MD4_get_IVs(M)
    
    #assert(bitget(A[5], 18) == bitget(C[4], 18))
    #assert(bitget(A[5], 25) == 1)
    #assert(bitget(A[5], 26) == 0)
    #assert(bitget(A[5], 28) == 1)    
    #assert(bitget(A[5], 31) == 1)
    
    return(MD4_get_data(M, endianness))

def Wang_fix_D5(data, do_padding=True, endianness='little'):
    
    #d5;19 = a5;19,   d5;26 = b4;26,   d5;27 = b4;27,   d5;29 = b4;29,   d5;32 = b4;32
    
    if do_padding:
        M = MD4_get_words(MD4_pad_data(data, endianness))
    else:
        if len(data) < 64:
            data += b'\x00'*(64-len(data))
        M = MD4_get_words(data, endianness) 
        
    A, B, C, D = MD4_get_IVs(M)
    
    D[5] = bitset(D[5], 18, bitget(A[5], 18))
    D[5] = bitset(D[5], 25, bitget(B[4], 25))
    D[5] = bitset(D[5], 26, bitget(B[4], 26))
    D[5] = bitset(D[5], 28, bitget(B[4], 28))
    D[5] = bitset(D[5], 31, bitget(B[4], 31))

def run_RFC_tests():
    
    assert(MD4('').hex() == '31d6cfe0d16ae931b73c59d7e0c089c0')
    assert(MD4('a').hex() == 'bde52cb31de33e46245e05fbdbd6fb24')
    assert(MD4('abc').hex() == 'a448017aaf21d8525fc10ae87aa6729d')
    assert(MD4('message digest').hex() == 'd9130a8164549fe818874806e1c7014b')
    assert(MD4('abcdefghijklmnopqrstuvwxyz').hex() == 'd79e1c308aa5bbcdeea8ed63df412da9')
    assert(MD4('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789').hex() == '043f8582f241db351ce627e153e7f0e4')
    assert(MD4('12345678901234567890123456789012345678901234567890123456789012345678901234567890').hex() == \
      'e33b4ddc9c38f2199c3e7b164fcc0536')

    print('If you can see this, all the tests passed.')    
    

def run_Wang_examples():
    
    # The examples in Table 3 of Wang's paper use big-endian byte order for the examples that
    # include message padding.  My MD4 uses little-endian.  I need a byte-swap function to fix 
    # the byte ordering...
        
    M_1_be = bytes.fromhex(
        '4d7a9c83 56cb927a b9d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f' 
        'c69d71b3 f9e99198 d79f805e a63bb2e8 45dd8e31 97e31fe5 2794bf08 b9e8c3e9')
    M_1_c_be = bytes.fromhex(
        '4d7a9c83 d6cb927a 29d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f' 
        'c69d71b3 f9e99198 d79f805e a63bb2e8 45dc8e31 97e31fe5 2794bf08 b9e8c3e9')
    M_1 = byte_swap(M_1_be, 4)
    M_1_c = byte_swap(M_1_c_be, 4)
    
    H_1 = bytes.fromhex('4d7e6a1d efa93d2d de05b45d 864c429b')
    H_1_np = bytes.fromhex('5f5c1a0d 71b36046 1b5435da 9b0d807a')
    
    M_2_be = bytes.fromhex(
        '4d7a9c83 56cb927a b9d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f' 
        'c69d71b3 f9e99198 d79f805e a63bb2e8 45dd8e31 97e31fe5 f713c240 a7b8cf69')
    M_2_c_be = bytes.fromhex(
        '4d7a9c83 d6cb927a 29d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f' 
        'c69d71b3 f9e99198 d79f805e a63bb2e8 45dc8e31 97e31fe5 f713c240 a7b8cf69')
    
    M_2 = byte_swap(M_2_be, 4)
    M_2_c = byte_swap(M_2_c_be, 4)
    
    H_2 = bytes.fromhex('c6f3b3fe 1f4833e0 697340fb 214fb9ea')
    H_2_np = bytes.fromhex('e0f76122 c429c56c ebb5e256 0b809793')
    
    # Check paper examples using default settings (padding + little endian byte-order)
    assert(MD4(M_1) == H_1)
    assert(MD4(M_1_c) == H_1)
    assert(MD4(M_2) == H_2)
    assert(MD4(M_2_c) == H_2)
    
    # Check paper examples using alternate settings (no padding + big endian byte-order)
    assert(MD4(M_1_be, False, 'big') == H_1_np)
    assert(MD4(M_1_c_be, False, 'big') == H_1_np)
    assert(MD4(M_2_be, False, 'big') == H_2_np)
    assert(MD4(M_2_c_be, False, 'big') == H_2_np)
    
    print('Wang Table 3 Tests passed')
    
    return(True)

