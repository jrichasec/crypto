import base64
import binascii
import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


password="passw0rd"

kdf = PBKDF2HMAC (
	algorithm=hashes.SHA256(),
	length=32,
	salt=b"salty",
	iterations=1203842,
	backend=default_backend()
)

key = base64.urlsafe_b64encode(kdf.derive(str.encode(password)))

f = Fernet(key)
encrypted_dat = f.encrypt(b"hell world test lolollololol")
print(encrypted_dat)
raw = binascii.hexlify(base64.urlsafe_b64decode(encrypted_dat))

ciphersize = int((len(raw)/2)*8-0x100-0x80-0x40-0x8)
version = raw[0:2]
timestamp = raw[2:2+(8*2)]
tsp = datetime.datetime.fromtimestamp(int(timestamp, 16))
iv = raw[2+(8*2):(2+(8*2))+(0x10*2)]
cipher = raw[(2+(8*2))+(0x10*2):(2+(8*2))+(0x10*2)+int((ciphersize/8)*2)]
hmac = raw[(2+(8*2))+(0x10*2)+int((ciphersize/8)*2):(2+(8*2))+(0x10*2)+int((ciphersize/8)*2)+0x100]

print("--- fernet info ---")
print("version:   ", version)
print("timestamp: ", timestamp)
print("           ", tsp)
print("iv:        ", iv)
print("cipher:    ", cipher)
print("hmac:      ", hmac)

