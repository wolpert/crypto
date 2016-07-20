# README #

CodeHead's Crypto Library

This library is the bases for encrypting other components that I'm using elsewhere.
The goal is to make this as open as possible so if I do anything stupid, other
people can comment.

## Supporting Strong Encryption ##

Doing encryption right is hard. My goal is for a limited feature set, create an
easy solution. Hash a password, create a crypto key, store the key and the
encrypted content. This does not handle trust, certs, or other cryptographic
features that are needed for a robust solution.

Passwords are hashed with SKEIN-512-256 hashing algo to generate the 256-bit key, which is
used with the AES crypto library. [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29)
for block chaining, and PKCS7 padding support. (Strings
converted with UTF-16LE charset)

The Hashing is done using the JCE library with Bouncy Castle provider support. The
encryption is done directly with Bouncy Castle libraries. (May remove JCE altogether
and replace SKEIN with SCrypt.)

Adding support to expire passwords forcing a user to re-enter in the password.

Uses the SecureRandom class for creating random bytes. If things run slow, this is why.
Create more entropy folks. Do not change that to the regular random class. That would be
dumb.

## JCE Notes ##

This library avoids the JCE key-length limiting 'feature' in the encryption process.

## Trust Me ##

Actually, do not trust me. Look at the code. See what it does and how it does it.
The encryption routines are fairly basic. The Hashing component will become simpler.
Comment on the github page if you have any suggestions.