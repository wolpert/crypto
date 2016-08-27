package com.codeheadsystems.crypto.manager;

import com.codeheadsystems.crypto.Decrypter;
import com.codeheadsystems.crypto.Encrypter;
import com.codeheadsystems.crypto.cipher.ParanoidDecrypter;
import com.codeheadsystems.crypto.cipher.ParanoidEncrypter;
import com.codeheadsystems.crypto.password.KeyParameterFactory;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.ParanoidKeyParameterFactory;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;
import com.codeheadsystems.crypto.timer.DefaultTimerProvider;
import com.codeheadsystems.crypto.timer.TimerProvider;

import org.bouncycastle.crypto.params.KeyParameter;

import java.io.IOException;

/**
 * Effectively a facade around the paranoid facilities.
 * BSD-Style License 2016
 */
public class ParanoidManager {

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
        KeyParameterFactory.AbstractKeyParameterFactoryBuilder builder = new ParanoidKeyParameterFactory.Builder();
        builder.timerProvider(timerProvider).iterationCount((int) Math.pow(2, 20));
        shortTermKeyParameterFactory = builder.expirationInMills(20000).build(); // 20 second
        longTermKeyParameterFactory = builder.expirationInMills(10 * 60 * 1000).build(); // 10 mins
    }

    public KeyParameter generateRandomAesKey() {
        return shortTermKeyParameterFactory.generateRandom256KeyParameter();
    }

    protected KeyParameterWrapper generatePrime(String password, byte[] salt) {
        return shortTermKeyParameterFactory.generate(password, salt);
    }

    public byte[] freshSalt() {
        return shortTermKeyParameterFactory.getSalt();
    }

    public SecondaryKey generateFreshSecondary(String password, byte[] salt) throws SecretKeyExpiredException {
        KeyParameterWrapper prime = generatePrime(password, salt);
        KeyParameterWrapper secondary = longTermKeyParameterFactory.generateRandom256KeyParameterWrapper();
        byte[] encryptedSecondary = encrypter.encryptBytes(prime, secondary.getKeyParameter().getKey());
        prime.expire();
        return new SecondaryKey(secondary, encryptedSecondary);
    }

    public SecondaryKey regenerateSecondary(String password, byte[] salt, byte[] encryptedSecondary) throws SecretKeyExpiredException {
        KeyParameterWrapper prime = generatePrime(password, salt);
        KeyParameterWrapper secondary = longTermKeyParameterFactory.getExpirableKeyParameterWrapper(new KeyParameter(decrypter.decryptBytes(prime, encryptedSecondary)));
        prime.expire();
        return new SecondaryKey(secondary, encryptedSecondary);
    }

    /**
     * End result is a encoded packet only the KeyParameterWrapper can decrypt
     *
     * @param sensitiveDetails Some string that needs encrypting
     * @param keyParameterWrapper The secret key to use for the encryption process
     * @return encrypted byte array suitable for storage
     * @throws IOException from compression failures
     * @throws SecretKeyExpiredException should the keyParameterWrapper already expired
     */
    public byte[] encode(String sensitiveDetails, KeyParameterWrapper keyParameterWrapper) throws IOException, SecretKeyExpiredException {
        byte[] compressedBytes = objectManipulator.compressString(sensitiveDetails);
        return encrypter.encryptBytes(keyParameterWrapper, compressedBytes);
    }

    public String decode(byte[] array, KeyParameterWrapper keyParameterWrapper) throws IOException, SecretKeyExpiredException {
        byte[] decryptedContent = decrypter.decryptBytes(keyParameterWrapper, array);
        return objectManipulator.uncompressString(decryptedContent);
    }

}
