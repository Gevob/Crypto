import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
from Crypto.Util.number import long_to_bytes
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import json, base64

HOST = '130.192.5.212'
PORT = 6561
if __name__ == '__main__':
    server = remote(HOST, PORT)
    idk = server.recvuntil("> ".encode())
    print(idk)
    seed = 10
    server.sendline(str(seed).encode())


    idk = server.recvline()
    print(idk)
    flag = server.recvline()
    flag = flag.strip() #flag cifrato
    print("flag")
    print(flag)
    idk = server.recv(1024)
    print(idk)
    server.sendline("y".encode())
    idk = server.recv(1024)
    print(idk)
    plaintext = b'C'*46
    print("plaintext")
    print(plaintext)
    server.sendline(plaintext)
    critto = server.recvline()
    critto = critto.strip()
    print("critto")
    print(critto)
    #print(len(idk))
    keystream = bytes(a ^ b for (a, b) in zip(critto, plaintext))
    #back = bytes(a ^ b for (a, b) in zip(critto, keystream))
    #print(back)
    print("keystream")
    print(keystream.decode())
    secret = bytes(a ^ b for (a, b) in zip(keystream, flag))
    print("secret")
    print(secret.decode())