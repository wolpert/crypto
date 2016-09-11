package com.codeheadsystems.crypto.manager;

import com.codeheadsystems.crypto.CryptoException;
import com.codeheadsystems.crypto.Decrypter;
import com.codeheadsystems.crypto.Encrypter;
import com.codeheadsystems.crypto.cipher.ParanoidDecrypter;
import com.codeheadsystems.crypto.cipher.ParanoidEncrypter;
import com.codeheadsystems.crypto.password.KeyParameterFactory;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.ScryptKeyParameterFactory;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;
import com.codeheadsystems.crypto.timer.DefaultTimerProvider;
import com.codeheadsystems.crypto.timer.TimerProvider;

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
        objectManipulator = new ObjectManipulator();
        TimerProvider timerProvider = new DefaultTimerProvider();
        encrypter = new ParanoidEncrypter();
        decrypter = new ParanoidDecrypter();
        KeyParameterFactory.AbstractKeyParameterFactoryBuilder builder = new ScryptKeyParameterFactory.Builder();
        builder.timerProvider(timerProvider).iterationCount((int) Math.pow(2, 20));
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
        return shortTermKeyParameterFactory.getSalt();
    }

    @Override
    public SecondaryKey generateFreshSecondary(String password) throws SecretKeyExpiredException, CryptoException {
        byte[] salt = freshSalt();
        KeyParameterWrapper prime = generatePrime(password, salt);
        KeyParameterWrapper secondary = longTermKeyParameterFactory.generateRandom256KeyParameterWrapper();
        byte[] encryptedSecondary = encrypter.encryptBytes(prime, secondary.getKeyParameter().getKey());
        prime.expire();
        return new SecondaryKey(secondary, encryptedSecondary, salt);
    }

    @Override
    public SecondaryKey regenerateSecondary(String password, byte[] salt, byte[] encryptedSecondary) throws SecretKeyExpiredException, CryptoException {
        KeyParameterWrapper prime = generatePrime(password, salt);
        KeyParameterWrapper secondary = longTermKeyParameterFactory.getExpirableKeyParameterWrapper(new KeyParameter(decrypter.decryptBytes(prime, encryptedSecondary)));
        prime.expire();
        return new SecondaryKey(secondary, encryptedSecondary, salt);
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
