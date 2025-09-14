"""
Module03_hash_ceasar_and_verify.py
by Paul Renaud
9/13/2025
For SDEV 345 Secure Coding

Instructions:
1. Choose a language (Python, Java, C/C++, or any language of your choice).
2. Write an app that generates SHA-256 hashes for input strings or files
3. Write an app that uses a simple substitution cipher (Caesar cipher or similar) to encrypt/decrypt input text
4. Use OpenSSL or a tool to simulate a digital signature (sign/verify).
5. Include a short README explaining your code's functionality
"""

from cryptography.hazmat.primitives import hashes  # for hasing and RSA encryption padding
from cryptography.hazmat.primitives.asymmetric import padding    # for OAEP padding
from cryptography.hazmat.primitives.asymmetric import rsa   # for asymmetric key-pairs
from cryptography import exceptions

DEFAULT_KEY = "D"  # default key for Vigenère cipher

# name ANSI colors for output
A_RED =     "\033[31m"
A_GREEN =   "\033[32m"
A_YELLOW =  "\033[33m"
A_BLUE =    "\033[34m"
A_MAGENTA = "\033[35m"
A_CYAN =    "\033[36m"
A_WHITE =   "\033[37m"
A_END =     "\033[0m"


def hash_from_text(text):
    # returns SHA-256 hash from given text
    digest = hashes.Hash(hashes.SHA256())
    digest.update(text.encode())
    return digest.finalize()

def hash_from_file(file):
    # returns SHA-256 hash bytestring from given file, or 0 if error.
    try:
        with open(file, "rb") as f:
            bytestring = f.read()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(bytestring)
        return digest.finalize()
    except FileNotFoundError:
        print("Error: The file", file , "was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
    return 0

def squash_key(key):
    # strips out spaces and all non-alpha characters from key. Defaults to DEFAULT_KEY if no letters present.
    final = ""
    for c in key:
        if c.isalpha(): final += c   # build key using only letters
    if final == "": final = DEFAULT_KEY   # default coded to A (no encryption), but can be changed above
    return final


def simple_encrypt(text, key):
    # encrypt text with the key, using simple substitution. Returns "encrypted" text.
    # only returns uppercase. key string repeats to match length of text.
    # key is a string. A is offset of 0, B is 1, C is 2, etc. Skips non-alpha characters (for easier copy/paste)
    key_pos = 0
    final = ""
    key = squash_key(key)  # remove all non-alpha characters from key
    key_len = len(key)
    text = text.upper()
    key = key.upper()
    for c in text:
        if c.isalpha():
            new_num = ord(c) + ord(key[key_pos]) - ord("A")  # add ascii values of textchar and keychar (offset by "A" value) together
            if new_num > ord("Z"):
                new_num -= 26  # wrap back to A if past Z
            new_c = chr(new_num)
            final += new_c
            key_pos += 1  # increment key position
            if key_pos >= key_len:
                key_pos = 0  # wrap key position back
        else:
            final += c
    return final

def simple_decrypt(text, key):
    # decrypt text with the key, using simple substitution. Returns unencrypted text.
    # key is any string, but it is stripped of non-alpha characters first.
    key_pos = 0
    final = ""
    key = squash_key(key)
    key_len = len(key)
    text = text.upper()
    key = key.upper()
    for c in text:
        if c.isalpha():
            new_num = ord(c) - ord(key[key_pos]) + ord("A")
            if new_num < ord("A"): new_num += 26  # wrap back to Z if past A
            new_c = chr(new_num)
            final += new_c
            key_pos += 1  # increment key position
            if key_pos >= key_len: key_pos = 0  # wrap key position back
        else:
            final += c
    return final

def sign_message(message, private_key):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_message(message, signature, public_key):
    try:
        public_key.verify(signature,
                                message,
                                padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
        )
        return True
    except exceptions.InvalidSignature:
        return False

if __name__ == "__main__":
    message = "Hello! This is supposed to be, like, a super-secret message."
    key = "It was the best of times, it was the worst of times"

    print("\nOriginal:", A_BLUE, message, A_END)

    print("Hash from text:", A_YELLOW, hash_from_text(message), A_END)
    input("\nPress Enter to demonstrate file hash.\n")

    file_name = "Module03_hash_ceasar_and_verify.py"
    print("Hash from file:", file_name, A_YELLOW, hash_from_file(file_name), A_END)
    input("\nPress Enter to encode/decode message using substitution cipher.\n")

    coded = simple_encrypt(message, key)
    print(" Encoded:", A_RED, coded, A_END)
    decoded = simple_decrypt(coded, key)
    print(" Decoded:", A_GREEN, decoded, A_END)
    input("\nPress Enter for Alice's signed message\n")

    # Generate keys for Alice
    alice_private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    alice_public_key = alice_private_key.public_key()

    # sign message with Alice's private key
    message = b"A message Alice wants to sign"
    print("Original message:", A_BLUE, message.decode(), A_END)
    signature = sign_message(message, alice_private_key)

    # "Send" Bob the message
    print("Signature:")
    print(A_MAGENTA, signature, A_END)
    input("Press Enter for Bob to verify signature with Alice's public key")

    changed_message = message + b" "
    verified = verify_message(changed_message, signature, alice_public_key)

    if verified:
        color = A_GREEN
    else:
        color = A_RED
    print("Changed message verified?", color, verified, A_END)
    
    verified = verify_message(message, signature, alice_public_key)

    if verified:
        color = A_GREEN
    else:
        color = A_RED
    print("Unchanged message verified?", color, verified, A_END)
