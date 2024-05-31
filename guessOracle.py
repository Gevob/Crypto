import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import json, base64

HOST ='130.192.5.212'
PORT =6541
if __name__ == '__main__':
    c=0
    server = remote(HOST, PORT)
    secret = ""
    for i in range(16):
        pad = b"a"*(AES.block_size-(i+1))
        pre = b"a"*(AES.block_size-1-len(secret))
        for letter in string.printable:
            msg = pre + secret.encode() + letter.encode() + pad
            #print(len(msg))
            c+=1
            if c % 50 == 0:
                print(c)
            msg = msg.hex().encode()
            idk = server.recvuntil("> ".encode())
            #print(idk)
            server.sendline("enc".encode())
            idk = server.recvuntil("> ".encode())
            #print(idk)
            #print(msg)
            server.sendline(msg)
            cypher = server.recvline().strip()

            #print(cypher)
            #cypher = server.recvline()
            #print(cypher)

            if cypher[:32] == cypher[32:64]:
                #print("I primi 16 byte sono uguali ai secondi 16 byte.")
                secret+=letter
                print(secret)
                c = 0
                break;
    print("next 16")
    for i in range(16):
        pad = b"a"*(AES.block_size-(i+1))
        pre = b"a"*((AES.block_size*2)-1-len(secret))
        for letter in string.printable:
            msg = pre + secret.encode() + letter.encode() + pad
            #print(len(msg))
            c+=1
            if c % 50 == 0:
                print(c)
            msg = msg.hex().encode()
            idk = server.recvuntil("> ".encode())
            #print(idk)
            server.sendline("enc".encode())
            idk = server.recvuntil("> ".encode())
            #print(idk)
            #print(msg)
            server.sendline(msg)
            cypher = server.recvline().strip()

            #print(cypher)
            #cypher = server.recvline()
            #print(cypher)

            if cypher[32:64] == cypher[96:128]:
                #print("I primi 16 byte sono uguali ai secondi 16 byte.")
                secret+=letter
                print(secret)
                c = 0
                break;
    print("last 14")
    for i in range(14):
        pad = b"a"*(AES.block_size-(i+1))
        pre = b"a"*((AES.block_size*3)-1-len(secret))
        for letter in string.printable:
            msg = pre + secret.encode() + letter.encode() + pad
            #print(len(msg))
            c+=1
            if c % 50 == 0:
                print(c)
            msg = msg.hex().encode()
            idk = server.recvuntil("> ".encode())
            #print(idk)
            server.sendline("enc".encode())
            idk = server.recvuntil("> ".encode())
            #print(idk)
            #print(msg)
            server.sendline(msg)
            cypher = server.recvline().strip()

            #print(cypher)
            #cypher = server.recvline()
            #print(cypher)

            if cypher[64:96] == cypher[160:192]:
                #print("I primi 16 byte sono uguali ai secondi 16 byte.")
                secret+=letter
                print(secret)
                c = 0
                break;