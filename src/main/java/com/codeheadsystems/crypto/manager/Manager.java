package com.codeheadsystems.crypto.manager;

import com.codeheadsystems.crypto.CryptoException;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;

import org.bouncycastle.crypto.params.KeyParameter;

import java.io.IOException;

/**
 * BSD-Style License 2016
 */
public interface Manager {

    /**
     * Generates a 256-bit random key, usable for bouncy castle
     *
     * @return KeyParameter containing the 256 random bits
     */
    KeyParameter generateRandomAesKey();

    /**
     * Generates a salt usable for password creation
     *
     * @return byte[]
     */
    byte[] freshSalt();

    /**
     * Provides a new, random 256-bit AES key that can be used to encrypt/decrypt content, encrypted
     * using the password provided.
     * THIS METHOD GENERATES THE SALT FRESH AS WELL.
     * This key is NOT the hashed password/salt combo. Uses Scrypt
     * for hashing the password/salt with large number of iterations, so it is slow. Uses the
     * random provider given to create the random data needed for the 256 bit key, and encrypts that
     * key. The KeyParameterWrapper provided by the secondary key will expire requiring to regenerate
     * the secondary key using the same password/salt and the encrypted secondary.
     *
     * @param password Endusers password. Should be non-trivial
     * @return A usable SecondaryKey for encrypting content. You must get the salt from the Secondary for storage, as well as the encrypted bytes
     * @throws SecretKeyExpiredException Though uncommon, can happen if the system is too slow to encrypt the secondary key.
     * @throws CryptoException           This will happen if the encryption fails.
     */
    SecondaryKey generateFreshSecondary(String password) throws SecretKeyExpiredException, CryptoException;

    /**
     * Given an existing encrypted byte set, will regenerate a SecondaryKey using the same password/salt combo
     * provided in the original generation.
     *
     * @param password           Endusers password. Should be non-trivial
     * @param salt               Salt used for this specific key. Salt should be the same salt used when originally created for this secondary key.
     * @param encryptedSecondary The bytes stored in the original SecondaryKey.
     * @return a new SecondaryKey with the proper contents needed for decrypting usagel
     * @throws SecretKeyExpiredException Though uncommon, can happen if the system is too slow to encrypt the secondary key.
     * @throws CryptoException           This will happen if the decryption of the encryptedSecondary fails.
     */
    SecondaryKey regenerateSecondary(String password, byte[] salt, byte[] encryptedSecondary) throws SecretKeyExpiredException, CryptoException;

    /**
     * Encode your text with this secondary key you used.
     *
     * @param sensitiveDetails Some string you care about. We will compress it.
     * @param secondaryKey     The secondary key to use to encrypt the string
     * @return byte[] containing the encrypted, compressed contents
     * @throws IOException               Can be thrown during compression. Not likely.
     * @throws SecretKeyExpiredException Will be thrown if the secondary key expired.
     * @throws CryptoException           This will happen if the encryption of the content fails fails.
     */
    byte[] encode(String sensitiveDetails, SecondaryKey secondaryKey) throws IOException, SecretKeyExpiredException, CryptoException;

    /**
     * Decodes the byte[] encrypted with this secondary key, returning decompressed string content.
     *
     * @param array        encrypted, compressed from the original text.
     * @param secondaryKey Secondary key to encrypt the byte[]
     * @return The string that was originally encrypted. Or random garbage if your key is wrong.
     * @throws IOException               Can be thrown during decompression. Likely if the key is bad.
     * @throws SecretKeyExpiredException Will be thrown if the secondary key expired.
     * @throws CryptoException           This will happen if the decryption of the content fails.
     */
    String decode(byte[] array, SecondaryKey secondaryKey) throws IOException, SecretKeyExpiredException, CryptoException;
}
