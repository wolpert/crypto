# README #

CodeHead's Crypto Library

This library is the bases for encrypting other components that I'm using elsewhere.
The goal is to make this as open as possible so if I do anything stupid, other
people can comment.

## TL; DR ##

Password hashed with SCrypt. Encryption via AES-256, CTR Mode, PKCS7 Padding.
Hashed passwords null out with inactivity.

## Supporting Strong Encryption ##

Doing encryption right is hard. My goal is for a limited feature set, create an
easy solution. Hash a password, create a crypto key, store the key and the
encrypted content. This does not handle trust, certs, or other cryptographic
features that are needed for a robust solution.

Passwords are hashed to generate the 256-bit key, which is used to encrypt and
decrypt with the AES crypto library. [CTR/SIC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29)
for block chaining, and PKCS7 padding support. (Strings converted with UTF-16LE charset)

The Hashing technique can be picked by the user. The default Paranoid impl uses SCrypt, but
the user can use a JCE-provided message digest, which we use SKEIN-512-256 by default.
We include the Bouncy Castle providers for the JCE, but use BC directly for encryption to
avoid the policy file requirement of the JCE.

Note that the MessageDigest version of the hasher does NOT use PBKDF2 standard, which was
not available in JDK7. It does default to 65536 iterations with 32-byte salt though.
If this bugs you, use the Paranoid mode.

Adding support to expire passwords forcing a user to re-enter in the password.
This is baked in at the lowest level so using this library just has to handle the
proper exception and reload with the users password.

Uses the SecureRandom class for creating random bytes. If things run slow, this is why.
Create more entropy folks. Do not change that to the regular random class. That would be
dumb.

## JCE Notes ##

This library avoids the JCE key-length limiting 'feature' in the encryption process.

You can optionally use a message digest via the JCE which will create a hasher with the
SKEIN-512-256 digester, or use the Paranoid one, which uses SCrypt without the JCE.

## Trust Me ##

Actually, do not trust me. Look at the code. See what it does and how it does it.
The encryption routines are fairly basic. The Hashing component will become simpler.
Comment on the github page if you have any suggestions.

## Gradle ##
    compile "com.codeheadsystems:crypto:0.5.0"

## Maven ##

    <dependency>
      <groupId>com.codeheadsystems</groupId>
      <artifactId>crypto</artifactId>
      <version>0.5.0</version>
    </dependency>

## Expected Use-case ##

Using the ParanoidManager, we hash your password and salt using SCrypt to create an AES key, known as
Primary. Primary is used to during the encryption process of truly randomly-created AES keys that store
your content, which are knows as Secondary. These Secondary keys encrypt the sensitive details, which
in our typical example, is usernames and passwords.

Primary is never long-lived in memory. Its purpose is to just provide access to a Secondary storage key.
Secondary may live longer in memory, but once Secondary times out, Primary will need to be regenerated again
from the users password and salt inorder to decrypt Secondary. This reduces the time where the password
and salt exist in memory.

Nothing stops multiple Secondary keys to exist, in fact, saving the details should regenerate new Secondary
keys over time.

NOTE: It is not determined if there is an advantage with using Secondary vs Prime to encode the base file.
You still have to store the encrypted Secondary. Does that help the basis for attack? (Having the
encrypted secondary and the file the unencrypted secondary encrypted?)

## Sample Usage ##

You do not have to use this library in the manner described above. Here are some
low-level ways to use the available pieces.

#### Encryption ####

In this example, we have the ParanoidKeyParameterFactory generates the salt for the hashing
of the password. You will need to store the salt. You can either save it with the
encrypted content or for the user. Regenerating it for the one encrypted content is
'more' secure then just with the user, but it will be a PITA. I quoted 'more' here
since its not necessary more secure. But it is your decision.

Note that the ParanoidKeyParameterFactory uses SCrypt for the hashing. The default is
2^20 iterations, which will take time. (Assume 5 seconds on fast hardware) 2^14 is the lowest number of
iterations allowed, which is sub-second.  This is why its paranoid folks.

The EncryptedByteHolder contains the encrypted bytes itself and the initialization vector
used. Both are needed to decrypt the content. You can retrieve a string representation of
the encrypted content via the toString() method on the EncryptedByteHolder.

        String clearText = "Super Important Text";
        KeyParameterFactory factory = new ParanoidKeyParameterFactory.Builder()
                .timerProvider(new DefaultTimerProvider())
                .expirationInMills(20000) // Expire keys in 20 seconds
                .build();
        String password = "lkfdsaf0oudsajhklfdsaf7ds0af7uaoshfkldsf9s67yfihsdka";
        byte[] salt = factory.getSalt();
        KeyParameterWrapper key = factory.generate(password, salt);
        Encrypter encrypter = new ParanoidEncrypter();
        byte[] encryptBytes = encrypter.encryptBytes(key, clearText);
        String stringVersionOfEncryptedBytes = Utilities.bytesToString(encryptBytes);
        
#### Decryption ####

Here, we used the same password and the previous used salt to decrypt the text.
We regenerate the EncryptedByteHolder from the previous string conversion of
the encrypted bytes.

        byte[] encryptedBytes = Utilities.stringToBytes(stringVersionOfEncryptedBytes);
        key = factory.generate(password, salt); // regenerate key if previous one expired
        Decrypter decrypter = new ParanoidDecrypter();
        String decryptedText = decrypter.decryptText(key, encryptedBytes);

#### Compression ####

The library does not compress strings automatically. You may want to in order to
save space or to reduce details exposed with encrypted compressed strings.
Remember, this library is not intended to be fast. It is intended to
be secure. So do not worry about any speed hit with compression. It is the least
of your problems.

Note that the ObjectConverter does provide a compression routine.

#### Misc ####

Converting bytes to a string is via base64 library provided by Bouncy Castle.
The Utilities library in this project wraps it. The salt is converted this way
to a string.