import base64
from argon2.low_level import hash_secret, Type
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

DATAFILE_NAME = "epm_data.enc"
KEYFILE_NAME = "epm_aes_key.key"
KEYSLTFILE_NAME = "epm_aes_key_salt.key"
IVFILE_NAME = "epm_aes_iv.key"

datafiles_path_prefix = os.environ["HOME"] + "/.local/share/epm/"

# Default underlaying low-level cryptography functions
backend = default_backend()

# Padding mechanisms
padder = padding.PKCS7(algorithms.AES.block_size).padder()
unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

# Data
datafile_fd = os.open(datafiles_path_prefix + DATAFILE_NAME, os.O_RDONLY)
enc_data_base64 = os.read(datafile_fd, os.stat(datafile_fd).st_size).decode()
enc_data = base64.b64decode(enc_data_base64)

# IV
ivfile_fd = os.open(datafiles_path_prefix + IVFILE_NAME, os.O_RDONLY)
iv_base64 = os.read(ivfile_fd, os.stat(ivfile_fd).st_size).decode()
iv = base64.b64decode(iv_base64)

# Salt
keystlfile_fd = os.open(datafiles_path_prefix + KEYSLTFILE_NAME, os.O_RDONLY)
salt_base64 = os.read(keystlfile_fd, os.stat(keystlfile_fd).st_size)
salt = base64.b64decode(salt_base64)

# Creates the private key by hashing plain private key with the salt in base64 binary buffer
argon_params = {
    "secret": b"337757", 
    "salt": salt,
    "time_cost": 4,
    "memory_cost": 1048576,
    "parallelism": 1,
    "hash_len": 32,
    "type": Type.ID }

argon_str = hash_secret(**argon_params).decode()

argon_hash_segment = argon_str.split("$")[-1]
argon_hash_segment_len = len(argon_hash_segment)
argon_hash_segment_padding = argon_hash_segment_len % 4
for i in range(argon_hash_segment_padding):
    argon_hash_segment += "="

private_key = base64.b64decode(argon_hash_segment)

cipher = Cipher(algorithms.AES(private_key), modes.CBC(iv), backend)
decryptor = cipher.decryptor()
plain_text = decryptor.update(enc_data) + decryptor.finalize()
print(plain_text.decode())
