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
    secret = ""
    idk = server.recvline()
    print(idk)
    flag = server.recvline()
    flag = flag.strip() #flag cifrato
    print("flag")
    print(flag)
    c = 0
    for i in range(46):
        pad = b"a"*(46-1-len(secret))
        for letter in string.printable:
            c+=1
            idk = server.recv(1024)
            #print(idk)
            server.sendline("y".encode())
            idk = server.recv(1024)
            #print(idk)
            plaintext = secret + letter + pad.decode()
            #print("plaintext")
            #print(plaintext)
            server.sendline(plaintext.encode())
            critto = server.recvline()
            critto = critto.strip()
            #print("critto")
            #print(critto)
            if c % 50 == 0:
                print(c)
            if critto[i*2:i*2+2] == flag[i*2:i*2+2]:
                secret+=letter
                print(secret)
                c = 0
                break;

