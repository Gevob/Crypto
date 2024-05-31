from base64 import b64decode
import numpy
from string import *

CHARACTER_FREQ = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}

encoded_ciphertexts = [
    "2cd8ac876f3c2f7fbadb18b112607df75de8c70450dc9bf46e8756e765b53a4cdceea0b8ce417f0656c99972bb2bd180cf6cb5fd036627ee24fde0ede7ecfcd739c206e4ed",
    "1ad5a4813b2c7c30b38e1ef9341459b646e39e0a29979bcd678913b07fb4330893e7e6f99a5a7f5445cc9f74ef38d29c8a6cbfe0037737e277fafeeaf4afe3926dde01f493b8",
    "08d1bc9d21327c39badc4ae639554ff750e8c5461ad2d9c526861fe27ee7354099e0b6b8d34f3a4f47858b70bc37999acf7faef7037036ab74fcf8e2fafbf19e6bdf00e6c7b8",
    "1fdcb0803b3a322cf98e0bff351442b846a7d34b129e9bd575c235c253970267ceb2bdb69a7e7f0656dd8c7da02bdbc0c123fbd84d766ff26bfbb7e7f2e3f8db6cc54e8b",
    "1bc2ac99263b3d33a6804ac634145eaf5af4c40a099bcfc8699702b079ac3f46dce2a9f4d55b360644cc8879a02ccace816caff04c7c2ee76dfaeea8b3f8fd8f71d91bf5c7b8",
    "0ad5a99d283c332aa68e08f8304715f91da7f1441ad2c2cf73c215f166ab765d8fa1a5ead344734852c98f3fef00d19bcf6faef04f766fea70e1faedf0aff69474d41dadc7b8",
    "01dfb0d438343b3af5d90be322181bae5cf290470b80dfc574ce56e965b2764b94e4a7ec96097b4857859078aa79ca81cf78a8b9427c2bab70fceea4e7e0b49678dd0ba192c173b1",
    "1ad5a99d2a23397fbcda4de2715254a513e8c5585e9dccce26841af16deb761accb0f1aa88192d0b55c19873e26d8cdf8b20e2ad172362ee66e8a5e7a3b6f6cf2c835aaf"
]

ciphertexts = [bytes.fromhex(encoded_ciphertexts[i]) for i in range(len(encoded_ciphertexts))]
print("stats")
print(len(ciphertexts))

longest_c = max(ciphertexts, key=len)
max_len = len(longest_c)
print(len(longest_c))

shortest_c = min(ciphertexts, key=len)
min_len = len(shortest_c)
print(len(shortest_c))


candidates_list = []

for byte_to_guess in range(max_len):
    freqs = numpy.zeros(256, dtype=float)

    for guessed_byte in range(256):
        for c in ciphertexts:
            if byte_to_guess >= len(c):
                continue
            if chr(c[byte_to_guess] ^ guessed_byte) in printable:
                freqs[guessed_byte] += CHARACTER_FREQ.get(chr(c[byte_to_guess] ^ guessed_byte).lower(), 0)

    max_matches = max(freqs)
    # print(max_matches)

    match_list = [(freqs[i], i) for i in range(256)]
    # print(match_list)
    ordered_match_list = sorted(match_list, reverse=True)
    # print(ordered_match_list)

    # candidates = []
    # for pair in ordered_match_list:
    #     if pair[0] < max_matches * .95:
    #         break
    #     candidates.append(pair)

    # print(candidates)
    candidates_list.append(ordered_match_list)

# for c in candidates_list:
#     print(c)


keystream = bytearray()
for x in candidates_list:
    keystream += x[0][1].to_bytes(1, byteorder='big') #estrai il valore numerico

from Crypto.Util.strxor import strxor

#
dec = keystream[28] ^ ciphertexts[3][28]
mask = dec ^ ord('Y')
keystream[28] = keystream[28] ^ mask

dec = keystream[17] ^ ciphertexts[2][17]
mask = dec ^ ord('o')
keystream[17] = keystream[17] ^ mask

dec = keystream[20] ^ ciphertexts[2][20]
mask = dec ^ ord('d')
keystream[20] = keystream[20] ^ mask

dec = keystream[38] ^ ciphertexts[0][38]
mask = dec ^ ord('e')
keystream[38] = keystream[38] ^ mask

dec = keystream[53] ^ ciphertexts[0][53]
mask = dec ^ ord('t')
keystream[53] = keystream[53] ^ mask

dec = keystream[43] ^ ciphertexts[1][43]
mask = dec ^ ord('e')
keystream[43] = keystream[43] ^ mask

dec = keystream[45] ^ ciphertexts[4][45]
mask = dec ^ ord('u')
keystream[45] = keystream[45] ^ mask

dec = keystream[46] ^ ciphertexts[2][46]
mask = dec ^ ord("'")
keystream[46] = keystream[46] ^ mask

dec = keystream[49] ^ ciphertexts[4][49]
mask = dec ^ ord('a')
keystream[49] = keystream[49] ^ mask

dec = keystream[57] ^ ciphertexts[3][57]
mask = dec ^ ord('u')
keystream[57] = keystream[57] ^ mask

dec = keystream[58] ^ ciphertexts[3][58]
mask = dec ^ ord(' ')
keystream[58] = keystream[58] ^ mask

dec = keystream[59] ^ ciphertexts[3][59]
mask = dec ^ ord('c')
keystream[59] = keystream[59] ^ mask

dec = keystream[65] ^ ciphertexts[3][65]
mask = dec ^ ord('s')
keystream[65] = keystream[65] ^ mask

dec = keystream[67] ^ ciphertexts[1][67]
mask = dec ^ ord('u')
keystream[67] = keystream[67] ^ mask

dec = keystream[0] ^ ciphertexts[4][0]
mask = dec ^ ord('c')
keystream[0] = keystream[0] ^ mask

dec = keystream[1] ^ ciphertexts[4][1]
mask = dec ^ ord('r')
keystream[1] = keystream[1] ^ mask

dec = keystream[2] ^ ciphertexts[4][2]
mask = dec ^ ord('i')
keystream[2] = keystream[2] ^ mask

dec = keystream[3] ^ ciphertexts[4][3]
mask = dec ^ ord('m')
keystream[3] = keystream[3] ^ mask

dec = keystream[5] ^ ciphertexts[4][5]
mask = dec ^ ord('n')
keystream[5] = keystream[5] ^ mask



for c in ciphertexts:
    l = min(len(keystream), len(c))
    print(strxor(c[:l], keystream[:l]))
