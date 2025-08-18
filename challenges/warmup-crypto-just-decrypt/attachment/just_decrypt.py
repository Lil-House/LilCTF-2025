"""Just Decrypt - A simple LilCTF warmup challenge."""

from random import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


FLAG = b""
key = Random(2025).randbytes(16)

print(AES.new(key, AES.MODE_CBC, iv=FLAG[9:25]).encrypt(pad(FLAG, 16)).hex())

# ae39cfab1ba8d38fc3761216c393caf16e3c3f13fe57e2dedd52f1b13072fa93df405c7e731a193cabe5fd88ee3241f79aded62d139faba8c767a3b8efc5a855
