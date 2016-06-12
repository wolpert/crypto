# README #

CodeHead's Crypto Library

This library is the bases for encrypting other components that I'm using elsewhere.
The goal is to make this as open as possible so if I do anything stupid, other
people can comment.  There will be a JWE/JWT component via Nimbus at some time... This
does not impact the interfaces that are designed to be easy once configured.

Take the pain out of encryption...

Doing encryption right is hard. My goal is for a limited feature set, create an
easy solution. Hash a password, create a crypto key, store the key and the
encrypted content. This does not handle trust, certs, or other cryptographic
features that are needed for a robust solution.

## API ##

The API here are basically interfaces and java classes representing how
to best handle different data that is planned to be used cryptographically.
The scope is small. Hashing of words, encrypting based on cryptographic keys.
The API does include a few implementations.

