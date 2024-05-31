import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
import json, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes, bytes_to_long

HOST ='130.192.5.212'
PORT =6552
fixed1 = b"username="
fixed2 = b"&admin="

if __name__ == '__main__':
    server = remote(HOST,PORT)
    username = b"prova"
    p1 = b"a"*(AES.block_size - len(fixed1))
    blocco = pad(b"true", AES.block_size)
    p2 = b"a"*(AES.block_size - len(fixed2))
    admin = server.sendline(p1+blocco+p2)
    res = int(server.recvline().decode().split(" ")[1])

    cookie = long_to_bytes(res)
    newcookie = cookie[:48]+cookie[16:32]
    print(newcookie)
    print(len(newcookie))
    message = server.recvlines(4)
    print(message)
    server.sendline(b"flag")
    sending = bytes_to_long(newcookie)
    server.sendline(str(sending).encode())
    message = server.recvlines(4)
    print(message)