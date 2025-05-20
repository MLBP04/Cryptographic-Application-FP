# Applied Cryptography Application

**Course:** Applied Cryptography - CSAC 329 Cryptographic Application  
**Date:** May 24, 2025

## Group Members

- Christine Kyla Belano
- Mark Laurence Pama
- Joshua Ean Valera

---

## Introduction

This project is a user-friendly cryptographic application that allows users to encrypt, decrypt, and hash messages or files using a variety of cryptographic algorithms. The purpose of this project is to demonstrate the practical application of cryptography for securing data and communications. Cryptography is essential in today's digital world to ensure confidentiality, integrity, and authenticity of information.

---

## How to Run

If you are unsure how to install dependencies or launch the application, please see [How-To-Run.txt](How-To-Run.txt) in this repository for detailed setup and usage instructions.

---

## Project Objectives

1. Implement multiple cryptographic algorithms (symmetric, asymmetric, and hashing) for both text and files.
2. Provide an intuitive graphical user interface for easy interaction with cryptographic functions.
3. Educate users about each algorithm by providing accessible information and background within the application.

---

## Discussions

### Application Architecture and UI Choice

The application is built using **Streamlit**, a Python-based framework for creating interactive web applications. Streamlit was chosen for its simplicity, rapid development capabilities, and ability to create clean, responsive UIs with minimal code. The app is organized into four main sections: Symmetric Encryption/Decryption, Asymmetric Encryption/Decryption, Hashing, and Algorithm Information. Each section is accessible via a sidebar navigation menu.

---

### Implemented Cryptographic Algorithms

#### 1. Block Cipher (XOR)
- **Type:** Symmetric
- **History/Background:** The XOR cipher is a simple symmetric encryption technique that uses the bitwise exclusive OR (XOR) operation. While not secure for serious cryptographic use, it demonstrates the basic principles of block ciphers and is useful for educational purposes.
- **Process:** Each byte of the plaintext is XORed with a corresponding byte of the key (repeating the key as needed) to produce the ciphertext. Decryption is performed by applying the same XOR operation with the same key.
- **Library:** Custom implementation in Python
- **Integration:** Used for both text and file encryption/decryption. Users provide a key, and the app handles the XOR operation.

#### 2. Caesar Cipher
- **Type:** Symmetric
- **History/Background:** The Caesar cipher is one of the simplest and oldest known encryption techniques, attributed to Julius Caesar, who used it to protect military messages.
- **Process:** Each letter in the plaintext is shifted by a fixed number of positions down the alphabet (the "key" or shift value).
- **Library:** Custom implementation in Python
- **Integration:** Used for text encryption/decryption. The user provides a shift value as the key.

#### 3. Vigenère Cipher
- **Type:** Symmetric
- **History/Background:** The Vigenère cipher is a classic polyalphabetic substitution cipher invented in the 16th century. It was considered unbreakable for centuries.
- **Process:** Each letter of the plaintext is shifted by the value of the corresponding letter in the repeating keyword.
- **Library:** Custom implementation in Python
- **Integration:** Used for text encryption/decryption. The user provides a keyword.

#### 4. RSA
- **Type:** Asymmetric
- **History/Background:** RSA was invented in 1977 by Rivest, Shamir, and Adleman. It is one of the first public-key cryptosystems and is widely used for secure data transmission.
- **Process:** RSA uses a pair of keys (public/private) for encryption and decryption based on the mathematical properties of large prime numbers.
- **Library:** PyCryptodome (`Crypto.PublicKey.RSA`, `Crypto.Cipher.PKCS1_OAEP`)
- **Integration:** Used for text encryption/decryption. The app can generate key pairs and allows users to input their own keys.

#### 5. Diffie-Hellman
- **Type:** Asymmetric (Key Exchange)
- **History/Background:** Proposed by Whitfield Diffie and Martin Hellman in 1976, it allows two parties to establish a shared secret over an insecure channel.
- **Process:** Both parties generate private/public keys and exchange public keys. Each computes the shared secret, which can be used as a symmetric key (e.g., for AES).
- **Library:** PyCryptodome (`Crypto.Random.random` for key generation), Python standard library for math
- **Integration:** Used for secure key exchange. The shared secret is used as an AES key for text encryption/decryption in the app.

#### 6. Hashing Functions (SHA-256, SHA-512, MD5, SHA-1)
- **Type:** Hash
- **History/Background:** Hash functions are used to produce a fixed-size digest from arbitrary data. SHA-256 and SHA-512 are part of the SHA-2 family (NIST, 2001). MD5 and SHA-1 are older and now considered insecure for collision resistance.
- **Process:** Input data is processed to produce a unique hash value (digest).
- **Library:** Python standard library (`hashlib`)
- **Integration:** Used for both text and file hashing. Users select the algorithm and input data or upload a file.

---

## How Algorithms Are Integrated

- Each algorithm is accessible via the app's sidebar.
- Users can input text or upload files, select the desired algorithm, and provide necessary keys or parameters.
- The app provides instant feedback and results, with options to download encrypted/decrypted files.
- The **"Algorithm Information"** section educates users about each algorithm, its background, and its use in the app.

---

## Sample Runs / Outputs

Below are text-based output examples for each algorithm's functionality.

### Symmetric Encryption/Decryption

#### Block Cipher (XOR)
**Input Text:**  
`Hello, World!`  
**Key:** `password`  
**Encrypted Output:**
```
38 04 1F 1F 18 43 52 33 1F 13 1F 17 56 30 2D 3B
```
**Decrypted Output:**
```
Hello, World!
```

#### Caesar Cipher
**Input Text:**  
`CRYPTOGRAPHY`  
**Key (Shift):** `3 4 5`  
**Encrypted Output:**
```
FV^SXTJVFSL^
```
**Decrypted Output:**
```
CRYPTOGRAPHY
```

#### Vigenère Cipher
**Input Text:**  
`CRYPTOGRAPHY`  
**Key:** `KEY`  
**ALPHABET:** `ZYXWVUTSRQPONMLKJIHGFEDCBA`
**Encrypted Output:**
```
NWXAYNRWZAMX
```
**Decrypted Output:**
```
CRYPTOGRAPHY
```

---

### Asymmetric Encryption/Decryption

#### RSA
**Input Text:**  
`Confidential`  
**Private Key:**  
`-----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----`  

**Public Key:**  
`-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----`  
**Encrypted Output:**
```
pKluNnjJTEJz9PoDcYreqGhIZzSps2TzY54ZJhWGhEuId8wTGIbSD6DsFsMHw/mZ7iCE7svLi13Q68mQBFcoeUdVXjlqnB7cuAOXp04ke6isjQJlqOgIgMBpbbmDvEabwRiFFoujVYybtwpJu+hb8W4CzoLr5KRSSPUoRMhqbX9kmom13FOym9572rkmT4VVXhGzTFV5UZIyAn8ottgWY2tpJ1Fh+eMsrWaWxTpJ4NrxUrhzJnjMzl6z6M43zSYN8MMp1ncM3jsZlr9X5IGDS7QeqEIMtwkNfKHi4x03iZ/ZNmt0fCihIjSj/7M666kTgMlsoxOs8JZXna3Emy6hZA==
```
**Decrypted Output:**
```
Confidential
```

#### Diffie-Hellman (with AES)
**Input Text:**  
`SharedSecretText`  
**Prime Number (P):**  
`23`  
**Primitive Root (G):**  
`9`  
**Alice's Private Key (a):**  
`4`  
**Bob's Private Key (b):**  
`3`  

**Step-by-step Key Exchange:**  
- Alice computes: `x = G^a mod P = 9^4 mod 23 = 6`  
- Bob computes: `y = G^b mod P = 9^3 mod 23 = 16`  
- Alice computes shared secret: `ka = y^a mod P = 16^4 mod 23 = 9`  
- Bob computes shared secret: `kb = x^b mod P = 6^3 mod 23 = 9`  
- **Shared secret established:** `9`  

### Hashing Functions

#### SHA-256 (Text)
**Input Text:**  
`hashme`  
**Output:**
```
02208b9403a87df9f4ed6b2ee2657efaa589026b4cce9accc8e8a5bf3d693c86
```

#### MD5 (File)
**Input File Content:**  
`This is a file.`  
**Output:**
```
6d432e1b8df49527390763d6ca834880
```

---

> *Note: The above outputs are for demonstration. Actual encrypted values will differ due to random IVs and keys.*

---

## References

- [PyCryptodome Documentation](https://www.pycryptodome.org/)
- [cryptography.io](https://cryptography.io/)
- [Python hashlib Documentation](https://docs.python.org/3/library/hashlib.html)
- [Wikipedia: Advanced Encryption Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [Wikipedia: Caesar cipher](https://en.wikipedia.org/wiki/Caesar_cipher)
- [Wikipedia: Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
- [Wikipedia: RSA (cryptosystem)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Wikipedia: Diffie–Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
- [Wikipedia: Cryptographic hash function](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
