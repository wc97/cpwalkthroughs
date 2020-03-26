import web
import sha1
import time
import cryptopals as cp

# Call using http://localhost:1234/?file=Test&signature=Test2
#
# Where 1234 is the port passed @ command line, i.e.:
#
#       python webpy_test.py 1234
#
# Here's a good test
#
# http://127.0.0.1:1234/?file=25.ipynb&signature=68105af4c1b8c32845079c3c06a32e9c0665ccb0


urls = ('/', 'index')
render = web.template.render('templates/')


#  HMAC_SHA1("key", "The quick brown fox jumps over the lazy dog")   =
#             de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9

HMAC_KEY = b'ABADKEY'

def HMAC(data, key):

    key_len = len(key)

    if key_len > 64:

        key = sha1.SHA(key).finish()

    elif key_len < 64:

        key = key + b'\x00'*(64-key_len)

    o_key_pad = cp.bitwise_xor(key, b'\x5c'*64)
    i_key_pad = cp.bitwise_xor(key, b'\x36'*64)

    pass_0_out = sha1.SHA1(i_key_pad + data).finish()
    pass_1_out = sha1.SHA1(o_key_pad + pass_0_out).finish()

    return(pass_1_out)


def insecure_compare(a, b, delay_time):

    # Return 500 for bad match
    # Return 200 for good match

    if len(a) != len(b):
        return(500)
        
    for a_i, b_i in zip(a, b):

        if a_i != b_i:
            return(500)
        time.sleep(delay_time)
        
    return(200)

class index:

    def GET(self):

        i = web.input(file=None, signature=None, delay_time=None)

        file_name = bytes(i.file, 'ascii')
        signature = i.signature
        delay_time = float(i.delay_time)
        
        f = open(file_name, 'r')
        data = bytes(f.read(), 'ascii')
        f.close()

        return_val = insecure_compare(HMAC(data, HMAC_KEY), bytes.fromhex(signature), delay_time)
        print(HMAC(data, HMAC_KEY).hex())
        return(return_val)

if __name__ == "__main__":

    app = web.application(urls, globals())
    app.run()
