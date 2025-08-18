from Crypto.Cipher import AES
from hashlib import md5
from params import vecs
from os import urandom

key = int("".join([vecs[int.from_bytes(urandom(2)) & 0xfff] for _ in range(50)]), 2)

print("🎁 :", [[nonce := int(urandom(50*2).hex(), 16), (bin(nonce & key).count("1")) % 2] for _ in range(600)])
print("🚩 :", AES.new(key=md5(str(key).encode()).digest(), nonce=b"Tiffany", mode=AES.MODE_CTR).encrypt(open("flag.txt", "rb").read()))