import base64
import os
import tempfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

MAGIC = b"TFY1"
NONCE_SIZE = 12
TAG_SIZE = 16
HEADER_SIZE = len(MAGIC) + NONCE_SIZE
CHUNK_SIZE = 64 * 1024
SPOOL_LIMIT = 8 * 1024 * 1024


class InvalidEncryptedFile(ValueError):
    pass


def _encryption_key():
    encoded_key = settings.FILE_ENCRYPTION_KEY
    if not encoded_key:
        raise ImproperlyConfigured("Set FILE_ENCRYPTION_KEY before uploading or downloading files.")
    return base64.urlsafe_b64decode(encoded_key.encode("ascii"))


def encrypt_file(source):
    key = _encryption_key()
    nonce = os.urandom(NONCE_SIZE)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encrypted_file = tempfile.SpooledTemporaryFile(max_size=SPOOL_LIMIT, mode="w+b")

    try:
        encrypted_file.write(MAGIC + nonce)
        for chunk in source.chunks(chunk_size=CHUNK_SIZE):
            encrypted_file.write(encryptor.update(chunk))
        encrypted_file.write(encryptor.finalize())
        encrypted_file.write(encryptor.tag)
        encrypted_file.seek(0)
        return encrypted_file
    except Exception:
        encrypted_file.close()
        raise


def decrypt_file(source):
    key = _encryption_key()
    source.seek(0, os.SEEK_END)
    encrypted_size = source.tell()
    if encrypted_size < HEADER_SIZE + TAG_SIZE:
        raise InvalidEncryptedFile("Encrypted file is truncated.")

    source.seek(0)
    header = source.read(HEADER_SIZE)
    if len(header) != HEADER_SIZE or header[: len(MAGIC)] != MAGIC:
        raise InvalidEncryptedFile("Encrypted file header is invalid.")

    nonce = header[len(MAGIC) :]
    source.seek(-TAG_SIZE, os.SEEK_END)
    tag = source.read(TAG_SIZE)
    source.seek(HEADER_SIZE)

    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    encrypted_bytes_left = encrypted_size - HEADER_SIZE - TAG_SIZE
    plaintext_file = tempfile.SpooledTemporaryFile(max_size=SPOOL_LIMIT, mode="w+b")

    try:
        while encrypted_bytes_left:
            chunk = source.read(min(CHUNK_SIZE, encrypted_bytes_left))
            if not chunk:
                raise InvalidEncryptedFile("Encrypted file is truncated.")
            plaintext_file.write(decryptor.update(chunk))
            encrypted_bytes_left -= len(chunk)

        plaintext_file.write(decryptor.finalize())
        plaintext_file.seek(0)
        return plaintext_file
    except Exception:
        plaintext_file.close()
        raise
