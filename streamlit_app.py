import streamlit as st
import hashlib
import base64
import io
import random
from math import gcd
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random.random import getrandbits
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding

st.title("Applied Cryptography Application")

MENU = [
    "Symmetric Encryption/Decryption",
    "Asymmetric Encryption/Decryption",
    "Hashing Functions",
    "Algorithm Informations"
]
choice = st.sidebar.selectbox("Navigation", MENU)

# --- Helper Functions ---
def pad(text, block_size):
    pad_len = block_size - len(text) % block_size
    return text + chr(pad_len) * pad_len

def unpad(text):
    pad_len = ord(text[-1])
    return text[:-pad_len]

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size).encode())
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def aes_decrypt(key, ciphertext):
    raw = base64.b64decode(ciphertext)
    iv = raw[:AES.block_size]
    ct = raw[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct).decode()
    return unpad(pt)
