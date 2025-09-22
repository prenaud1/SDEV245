Module04 README.txt
for Module04_secure_data_transmission.py
by Paul Renaud
9/22/2025
For SDEV 245 Secure Coding

This Python program demonstrates hashing and symmetric encryption, and then decryption and verifying the hash. This
program displays in a terminal, and uses keyboard input. It uses ANSI colors. The encrypt and decrypt functions return bytes
or strings, so these functions could be used in a GUI environment without altering them. (except hash_from_file(), which is
not used in this program.) This is similar to my last program from Module 03.

To run this you will need to pip install cryptography in your environment.

The first time this program is run in a new environment, uncomment the first line in main, so a call is made to new_key().
This will generate a new symmetric key and save it to a local file. After this initial run, you may comment it out again and
it will load the key from the locally saved file on subsequent runs. In a more feature-rich program, this would be an option
to generate a new key on demand.

The program runs in several parts, with pauses to press Enter between sections to give you a chance to read what it is doing.

1. Enter a message to encrypt. It can be multiple lines. Finish by typing done by itself on a line (case-sensitive, can be
   changed in the code) or by enterting three blank lines. The blank lines will be stripped before saving the message.

2. The program will return a SHA-256 hash of your message. This is saved to variable sent_hash.

3. The program will encrypt the message using the Fernet section of the cryptography library. According to the Fernet docs,
   this encrypts with AES in CBC mode with a 128-bit key for encryption; using PKCS7 padding. The encrypted message will
   display.

4. The message will be decrypted, using the same symmetric key. The decrypted message is shown.

5. A new hash will be created from the decrypted message, saved to variable received_hash, and compared to sent_hash. If
   they match, it will say True. Otherwise, it will show False.

---

Here is how this program demonstrates parts of the CIA Triad (confidentiality, integrity, and availability).

Condidentiality - Only someone with the key used to encrypt the message can decrypt it. This protects the message's
confidentiality.

Integrity - The contents of the message can be shown to not be altered by comparing the hash from before and after
the transmission of the encrypted message. The hash would also need to be sent, but it does not need to be encrypted as
a message cannot be recovered from just the hash.

Availability - This program does not deal directly with availability, as access to the message (encrypted or not) is
not ensured (backups, etc.). However, if the hash is received but the message is not, or if the message was corrupted
during transmission and the hashes don't match, the receiver can ask for it to be resent.

Entropy and key generation are handled by the cryptography library, but here is what I found out.
When generating a new key, Fernet returns base64.urlsafe_b64encode(os.urandom(32)). This uses the operating system's
built-in cryptographically secure random number generator, rather than simply a pseudo-random number generator. This
will change based on what system this is run on, but except in cases of a system with a shallow entropy pool (like
running on a low-power device or one with insufficient on-time) this should be fine.

---

Notes on the video recording:
The program is run twice. The first time only a single letter is hashed and encrypted, and uses the 3 blank lines to
signal the end of the message. The second time it uses the signal keyword (done) to mark the end of the message, and
shows multiple lines can be sent.