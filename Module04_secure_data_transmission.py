"""
Module04_secure_data_transmission.py
by Paul Renaud
9/21/2025
For SDEV 245 Secure Coding

1. Accepts user input (e.g., a message or file). This version only accepts a message.
2. Hashes the input using SHA-256 to ensure integrity
3. Encrypts the input using symmetric encryption (e.g., AES)
4. Decrypts the content and verifies its integrity via hash comparison

Write a short explanation describing how their solution upholds confidentiality, integrity, and availability
Explain the role of entropy and key generation in their implementation
"""

from cryptography.fernet import Fernet   # for symmetric key
from cryptography.hazmat.primitives import hashes  # for generating hashes
from cryptography.hazmat.primitives.asymmetric import padding    # for OAEP padding
from cryptography.hazmat.primitives.asymmetric import rsa   # for asymmetric key-pairs


# name ANSI colors for output
A_RED =     "\033[31m"
A_GREEN =   "\033[32m"
A_YELLOW =  "\033[33m"
A_BLUE =    "\033[34m"
A_MAGENTA = "\033[35m"
A_CYAN =    "\033[36m"
A_WHITE =   "\033[37m"
A_END =     "\033[0m"

def new_key():
    # Creates and saves a new symmetric key. Only run this the first time. Otherwise, it will be different each time.
    key = Fernet.generate_key()
    with open("module04.key", "wb") as f:
        f.write(key)

def load_key():
    # Loads previously saved key.
    key = None
    with open("module04.key", "rb") as f:
        key = f.read()
    return key

def encrypt_text(plaintext):
    # Accepts string to encrypt. Returns encrypted version of plaintext, as a bytestring.
    # Uses Fernet, a form of AES encryption.
    key = load_key()
    byte_text = plaintext.encode()  # convert to bytes for encryption
    fn_suite = Fernet(key)
    ciphertext = fn_suite.encrypt(byte_text)
    return ciphertext

def decrypt_text(ciphertext):
    # Accepts bytestring to decrypt. Returns plaintext version of ciphertext.
    # Uses Fernet, a form of AES encryption.
    key = load_key()
    fn_suite = Fernet(key)
    plaintext = fn_suite.decrypt(ciphertext).decode()  # decode converts back to string from bytes
    return plaintext

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

# begin main program operation
if __name__ == "__main__":
    # new_key()    # executed only once and saved to file for symmetric key
    load_key()
    done_string = "done"
    print("Enter the message you want to encrypt. Multiple lines are allowed.")
    print("Type 3 blank lines or " + A_RED + done_string + A_END + " by itself on a line to quit.")
    last_line = ""
    message = ""
    blanks = 0
    print(A_BLUE, end="")
    while last_line != done_string:
        last_line = input()  # get each line of input...
        if last_line != done_string:
            message += last_line + "\n"  # ...and add to message.
        else:
            message = message[:-1]  # slices off last extra \n if done. Still safe is string is empty.
        if last_line == "":
            blanks += 1   # count blank lines
        else:
            blanks = 0   # reset blank lines
        if blanks >= 3:  # end if multiple blank lines in a row
            message = message[:-4]  # slices off the last four \n.
            break
    print(A_END, end="")
    print("Message saved.", len(message), "character" + ("" if len(message)==1 else "s") + ".")
    input("Press Enter")

    print("\nMessage hash:")
    sent_hash = hash_from_text(message)
    print(A_YELLOW, sent_hash, A_END, sep="")
    input("Press Enter")

    print("Encypting message...", end="")
    ciphertext = encrypt_text(message)
    print("done.")
    print("Encrypted message follows:")
    print(A_RED, ciphertext, A_END, sep="")
    input("Press Enter")

    print("Decrypting message...", end="")
    received_message = decrypt_text(ciphertext)
    print("done.")
    print("Decrypted message follows:")
    print(A_GREEN, received_message, A_END, sep="")
    input("Press Enter")

    print("Received message hash:")
    received_hash = hash_from_text(received_message)
    print(A_YELLOW, received_hash, A_END, sep="")

    verified = False
    if sent_hash == received_hash:
        verified = True
        color = A_GREEN
    else:
        verified = False
        color = A_RED
    print("Hashes match: ", color, verified, A_END, sep="")
