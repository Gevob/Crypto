import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from base64 import *
from Crypto.Cipher import AES
import string

import binascii

HOST = '130.192.5.212'
PORT = 6541
FLAG_LEN = 36 + len("CRYPTO23{}")


secret = ""
prefix = "1"*94
fix= "1"*94
# server = remote(HOST, PORT)
# for letter in string.printable:
#     ans=server.recvuntil(">")
#     print(ans)
#     server.sendline("enc")
#     ans=server.recvuntil(">")
#     print(ans)
#     msg=prefix+hex(ord(letter))[2:]+fix
#     print(hex(ord(letter))[2:])
#     server.sendline(msg)
#     ciphertext = server.recvline()
#     print(ciphertext[65:97])
#     print(ciphertext[161:193])
#     if ciphertext[65:97] == ciphertext[161:193]:
#         print(letter)
#         break;
#         print(ciphertext[1:33])
#         print(ciphertext[33:65])
#         print(ciphertext[65:97])
#         print(ciphertext[97:129])
#         print(ciphertext[129:161])
#         print(ciphertext[161:193])
server = remote(HOST, PORT)
cont = 96
for i in range(0,FLAG_LEN):
     cont = cont -2
     pad = "1"*cont
     for letter in string.printable:
         ans=server.recvuntil(">".encode())
         #print(ans)
         msg=prefix+secret+hex(ord(letter))[2:]+pad
#         print("Sending: "+msg)
#         print(len(msg))
         server.sendline("enc".encode())
         ans=server.recvuntil(">".encode())
#         #print(ans)
         server.sendline(msg)
         ciphertext = server.recvline(1024)
         #print(ciphertext[65:97])
         #print(ciphertext[161:193])
         if ciphertext[65:97] == ciphertext[161:193]:
             print("Found new character = "+letter)
             secret+=hex(ord(letter))[2:]
             prefix = prefix[2:]
             break
print("Secret discovered = ")
print(bytes.fromhex(secret))