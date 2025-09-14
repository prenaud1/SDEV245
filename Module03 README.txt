Module03 README.txt
by Paul Renaud
9/14/2025
for SDEV 245

This python program demonstrates the following items:
    Generates SHA-256 hashes for input strings or files
    Uses a simple substitution cipher (Caesar cipher or similar) to encrypt/decrypt input text
    Use a tool to simulate a digital signature (sign/verify).

To run this program the library "cryptography" is required to be installed.
This program outputs to a terminal, and waits for Enter to be pressed between sections. It uses ANSI color codes.

The program runs in several parts.

    1. First it displays some text and then shows the SHA-256 hash of it.

    2. Next it shows a hash of a file: in this case, itself.

    3. Then it encodes and decodes some text using the Vigenere cipher. To make it a simple Ceaser cipher, set the key
    to only use one letter (like "N"). The key can be any string, but only alpha characters are used. If no alpha
    characters are present, it defaults to "D".

    4. A new message is created for Alice to send to Bob. The message is not encrypted, but a signature on that message,
    signed with Alice's private key, is sent as well.

    5. Bob "receives" the message (prints to terminal), and verifies it was Alice who sent it by using Alice's public key.
    To test the verification process, I added a space to the message that Bob checks. This fails the verificiation. When
    tested with the original message, it passes.

