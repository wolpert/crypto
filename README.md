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

## Sample Usage ##

#### Encryption ####

In this example, we have the KeyParameterFactory generate the salt for the hashing
of the password. You will need to store the salt. You can either save it with the 
encrypted content or for the user. Regenerating it for the one encrypted content is
'more' secure then just with the user, but it will be a PITA. I quoted 'more' here
since its not necessary more secure. But it is your decision.

The EncryptedByteHolder contains the encrypted bytes itself and the initialization vector
used. Both are needed to decrypt the content. You can retrieve a string representation of
the encrypted content via the toString() method on the EncryptedByteHolder.

        String password = "lkfdsaf0oudsajhklfdsaf7ds0af7uaoshfkldsf9s67yfihsdka";
        String clearText = "Super Important Text";
        KeyParameterWrapper parameterWrapper = new KeyParameterFactory().generate(password);
        Encrypter encrypter = new ParanoidEncrypter(parameterWrapper);
        EncryptedByteHolder encryptBytes = encrypter.encryptBytes(clearText);
        String salt = encryptKeyParameterWrapper.getSaltAsString()
        
        String stringVersionOfEncryptedBytes = encryptBytes.toString()
        
#### Decryption ####

Here, we used the same password and the previous used salt to decrypt the text.
We regenerate the EncryptedByteHolder from the previous string conversion of
the encrypted bytes.

        byte[] encryptedBytes = EncryptedByteHolder.fromString(stringVersionOfEncryptedBytes)
        Decrypter decrypter = new ParanoidDecrypter(new KeyParameterFactory().generate(password, salt));
        String decryptedText = decrypter.decryptText(encryptBytes);

#### Compression ####

The library does not compress strings automatically. You may want to to help
save space.  Remember, this library is not intended to be fast. It is intended to
be secure. So do not worry about any speed hit with compression. It is the least
of your problems.

#### Misc ####

Converting bytes to a string is via base64 library provided by Bouncy Castle.
The Utilities library in this project wraps it. The salt is converted this way
to a string.