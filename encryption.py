"""
Encrypted File Transfer Server
encryption.py: encryption functions for Encrypted File Transfer server usage.
"""

__author__ = "Arthur Rennert"

from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def create_aes_key():
    key = get_random_bytes(16)
    return key


def encrypt_aes_key_with_rsa_key(data, key):
    recipient_key = RSA.importKey(key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(data)
    return enc_session_key
