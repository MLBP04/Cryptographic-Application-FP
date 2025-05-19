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
