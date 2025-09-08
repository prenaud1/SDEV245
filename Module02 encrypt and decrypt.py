"""
Module02 encrypt decrypt.py
by Paul Renaud
9/6/2025
for SDEV 245 Secure Coding
"""

from cryptography.fernet import Fernet   # for symmetric key
from cryptography.hazmat.primitives import hashes  # for RSA encryption and padding
from cryptography.hazmat.primitives.asymmetric import padding    # for OAEP padding
from cryptography.hazmat.primitives.asymmetric import rsa   # for asymmetric key-pairs

# Global variables.
plaintext = ("The surprise party for your brother will be on Friday at 5:30pm.\n"
            "Your mission is to stall him after work, so we have time to set up.\n"
            "Come hungry, as we ordered a bunch of pizzas.")

# name ANSI colors for output
A_RED =     "\033[31m"
A_GREEN =   "\033[32m"
A_YELLOW =  "\033[33m"
A_BLUE =    "\033[34m"
A_MAGENTA = "\033[35m"
A_CYAN =    "\033[36m"
A_WHITE =   "\033[37m"
A_CLEAR =   "\033[0m"

def new_key():
    # Creates and saves a new symmetric key. Only run this the first time. Otherwise, it will be different each time.
    key = Fernet.generate_key()
    with open("module02.key", "wb") as f:
        f.write(key)

def load_key():
    # Loads previously saved key.
    key = None
    with open("module02.key", "rb") as f:
        key = f.read()
    return key

def encrypt_text(plaintext):
    # Accepts string to encrypt. Returns encrypted version of plaintext, as a bytestring.
    key = load_key()
    byte_text = plaintext.encode()  # convert to bytes for encryption
    fn_suite = Fernet(key)
    ciphertext = fn_suite.encrypt(byte_text)
    return ciphertext

def decrypt_text(ciphertext):
    # Accepts bytestring to decrypt. Returns plaintext version of ciphertext.
    key = load_key()
    fn_suite = Fernet(key)
    plaintext = fn_suite.decrypt(ciphertext).decode()  # decode converts back to string from bytes
    return plaintext

if __name__ == "__main__":
    # new_key()    # executed only once and saved to file for symmetric key

    print("Original message")
    print(A_BLUE + plaintext + A_CLEAR)
    input("\nPress enter to encrypt\n")

    ciphertext = encrypt_text(plaintext)
    print("Encrypted message")
    print(A_RED, ciphertext, A_CLEAR, sep="")  # commas needed here instead of + because encrypted is bytes
    input("\nPress enter to decrypt\n")

    plaintext = decrypt_text(ciphertext)
    print("Decrypted message")
    print(A_GREEN + plaintext + A_CLEAR)
    input("\nPress enter to continue to RSA asymmetric keys")

    print("\n------------------Asymmetric keys-----------------")

    ciphertext = ""   # reset to blank, so old value doesn't carry over, just in case
    
    # Generate keys for Alice
    alice_private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    alice_public_key = alice_private_key.public_key()

    # Generate keys for Bob
    bob_private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    bob_public_key = bob_private_key.public_key()

    print("Original message (from Alice to Bob)")
    print(A_BLUE, plaintext, A_CLEAR, sep="")
    input("\nPress Enter to encrypt with Bob's public key\n")
    
    # Encrypt the message using Bob's public key
    ciphertext = bob_public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("Encrypted message")
    print(A_RED, ciphertext, A_CLEAR, sep="")
    input("\nPress enter to decrypt using Bob's private key\n")

    # Decode the message using Bob's private key
    decoded = bob_private_key.decrypt(ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).decode()

    print("Decrypted message")
    print(A_GREEN + decoded + A_CLEAR)
    input("\nPress enter to quit\n")
    