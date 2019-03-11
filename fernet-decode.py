# Fernet token generator & with metadata decoding


from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import sys
import binascii
import base64
import datetime
import hashlib

password="123"
message="hello world"
# SHA256 key generation from password, pretty shitty method, PBKDF2 preferred 
def genkey(passwd):
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(str.encode(passwd))
	return base64.urlsafe_b64encode(digest.finalize())

def genPBKDF2(passwd): 
	dk = hashlib.pbkdf2_hmac('sha256',
			    str.encode(passwd),
			    str.encode("salt"),
			    1024
	)
	return base64.urlsafe_b64encode(dk)

if len(password) > 0:
	key = genPBKDF2(password)
else:
	key = Fernet.generate_key()

fernObj = Fernet(key)
ciphertext = fernObj.encrypt(str.encode(message))
print("====== DECODE INFO =====")
raw = base64.urlsafe_b64decode(ciphertext)
rawstring = binascii.hexlify(raw)
bytelen = len(raw)

# Total minus overheads(IV/HMAC/VERSION/TIMESTAMP)
cipherlen = (bytelen*8)-256-128-8-64
offset = 50+((int(cipherlen/8))*2)

version = rawstring[0:2]
timestamp = rawstring[2:18]
dt = datetime.datetime.fromtimestamp(int(timestamp.decode(), 16))
init_vector = rawstring[18:50]
ciphertextdec = rawstring[50:offset]
hmac = rawstring[offset::]
print("Version:           ", version.decode())
print("Timestamp:         ", timestamp.decode())
print("Timestamp(parsed): ", dt)
print("IV:                ", init_vector.decode())
print("Cipher:            ", ciphertextdec.decode())
print("HMAC:              ", hmac.decode())
print("Fernet token:      ", ciphertext.decode())
