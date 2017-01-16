package com.codeheadsystems.crypto.manager;

import com.codeheadsystems.crypto.CryptoException;
import com.codeheadsystems.crypto.Decrypter;
import com.codeheadsystems.crypto.Encrypter;
import com.codeheadsystems.crypto.cipher.CipherProvider;
import com.codeheadsystems.crypto.cipher.ParanoidDecrypter;
import com.codeheadsystems.crypto.cipher.ParanoidEncrypter;
import com.codeheadsystems.crypto.password.KeyParameterFactory;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;

import org.bouncycastle.crypto.params.KeyParameter;

import java.io.IOException;

/**
 * Effectively a facade around the paranoid facilities. Note that this class does not guarantee
 * that the random provider is secure. Use SecureParanoidManager instead.
 * BSD-Style License 2016
 */
public class ParanoidManager implements Manager {

    private final KeyParameterFactory shortTermKeyParameterFactory; // used for short-lived passwords decoding
    private final KeyParameterFactory longTermKeyParameterFactory; // used for the longer term password file
    private final Encrypter encrypter;
    private final Decrypter decrypter;
    private final ObjectManipulator objectManipulator;

    public ParanoidManager() {
        this(20);
    }

    public ParanoidManager(int iterationExponential) {
        objectManipulator = new ObjectManipulator();
        CipherProvider cipherProvider = new CipherProvider();
        encrypter = new ParanoidEncrypter(cipherProvider);
        decrypter = new ParanoidDecrypter(cipherProvider);
        KeyParameterFactory.Builder builder = new KeyParameterFactory.Builder();
        builder.iterationCount((int) Math.pow(2, iterationExponential));
        shortTermKeyParameterFactory = builder.expirationInMills(20000).build(); // 20 second
        longTermKeyParameterFactory = builder.expirationInMills(10 * 60 * 1000).build(); // 10 mins
    }

    @Override
    public KeyParameter generateRandomAesKey() {
        return shortTermKeyParameterFactory.generateRandom256KeyParameter();
    }

    protected KeyParameterWrapper generatePrime(String password, byte[] salt) {
        return shortTermKeyParameterFactory.generate(password, salt);
    }

    @Override
    public byte[] freshSalt() {
        return CipherProvider.getSalt();
    }

    @Override
    public SecondaryKey generateFreshSecondary(String password) throws SecretKeyExpiredException, CryptoException {
        byte[] salt = freshSalt();
        KeyParameterWrapper prime = generatePrime(password, salt);
        KeyParameterWrapper secondary = longTermKeyParameterFactory.generateRandom256KeyParameterWrapper();
        byte[] encryptedSecondary = encrypter.encryptBytes(prime, secondary.getKey());
        prime.expire();
        return new SecondaryKey(secondary, encryptedSecondary, salt);
    }

    @Override
    public SecondaryKey generateFreshSecondary(SecondaryKey secondaryKey) throws SecretKeyExpiredException, CryptoException {
        KeyParameterWrapper newSecondary = longTermKeyParameterFactory.generateRandom256KeyParameterWrapper();
        byte[] encryptedSecondary = encrypter.encryptBytes(secondaryKey.getKeyParameterWrapper(), newSecondary.getKey());
        return new SecondaryKey(newSecondary, encryptedSecondary, null);
    }

    @Override
    public SecondaryKey regenerateSecondary(String password, byte[] salt, byte[] encryptedSecondary) throws SecretKeyExpiredException, CryptoException {
        KeyParameterWrapper prime = generatePrime(password, salt);
        KeyParameterWrapper secondary = longTermKeyParameterFactory.getExpirableKeyParameterWrapper(new KeyParameter(decrypter.decryptBytes(prime, encryptedSecondary)));
        prime.expire();
        return new SecondaryKey(secondary, encryptedSecondary, salt);
    }

    @Override
    public SecondaryKey regenerateSecondary(SecondaryKey encryptingSecondaryKey, byte[] encryptedSecondary) throws SecretKeyExpiredException, CryptoException {
        KeyParameterWrapper secondary = longTermKeyParameterFactory.getExpirableKeyParameterWrapper(new KeyParameter(decrypter.decryptBytes(encryptingSecondaryKey.getKeyParameterWrapper(), encryptedSecondary)));
        return new SecondaryKey(secondary, encryptedSecondary, null);
    }

    @Override
    public byte[] encode(String sensitiveDetails, SecondaryKey secondaryKey) throws IOException, SecretKeyExpiredException, CryptoException {
        byte[] compressedBytes = objectManipulator.compressString(sensitiveDetails);
        return encrypter.encryptBytes(secondaryKey.getKeyParameterWrapper(), compressedBytes);
    }

    @Override
    public String decode(byte[] array, SecondaryKey secondaryKey) throws IOException, SecretKeyExpiredException, CryptoException {
        byte[] decryptedContent = decrypter.decryptBytes(secondaryKey.getKeyParameterWrapper(), array);
        return objectManipulator.uncompressString(decryptedContent);
    }

}
