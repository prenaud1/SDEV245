Module02 encrypt decrypt.py
by Paul Renaud
9/6/2025
for SDEV 245 Secure Coding

This simple program is to demonstrate encrypting and decrypting some short text using both a symmetric key
(the same key used to encrypt and decrypt the message) and asymmetric keys (public key to encrypt, and private
key to decrypt). Thie program outputs to a terminal.

To run this you will need to install the library cryptography. This is included in requirements.txt.

Program walkthrough
Upon first run, a symmetric key was generated and saved to a file for later. Then this line was commented
out for future runs of the program, and the key is loaded from the saved file instead.

A secret, multi-line message about a surprise party is hard-coded near the top.

Each of the following steps waits for line input (just press enter) before continuing.

Symmetric key encryption/decryption
First the original text is displayed. If your terminal is ANSI compatible it will display in blue.
The text is encrypted with the key, and the encrypted text is shown in red. It will start with a b', as it
is a bytestring.
Next the text is decrypted with the key, and this is shown in green.

Asymmetric key encryption/decryption
Alice wants to send this message to Bob. First the original message is displayed.
It is encrypted using Bob's public key. The encrypted message is shown as a bytestring.
Bob decrypts it with his private key. The decrypted message is shown.

The program waits for a final line input to end.
