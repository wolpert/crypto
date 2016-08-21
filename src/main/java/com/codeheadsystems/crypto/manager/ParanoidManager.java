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
 *
 * <p/>
 * BSD-Style License 2016
 */
public class ParanoidManager {

    private final TimerProvider timerProvider;
    private final KeyParameterFactory shortTermKeyParameterFactory; // used for short-lived passwords decoding
    private final KeyParameterFactory longTermKeyParameterFactory; // used for the longer term password file
    private final Encrypter encrypter;
    private final Decrypter decrypter;
    private final ObjectConverter objectConverter;

    public ParanoidManager() {
        objectConverter = new ObjectConverter();
        timerProvider = new DefaultTimerProvider();
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

    /**
     * End result is a encoded packet only the KeyParameterWrapper can decrypt
     *
     * @param sensitiveDetails
     * @param keyParameterWrapper
     * @return
     * @throws IOException
     * @throws SecretKeyExpiredException
     */
    public byte[] encode(SensitiveDetails sensitiveDetails, KeyParameterWrapper keyParameterWrapper) throws IOException, SecretKeyExpiredException {
        byte[] compressedBytes = objectConverter.toByteArray(sensitiveDetails);
        return encrypter.encryptBytes(keyParameterWrapper, compressedBytes);
    }

    public SensitiveDetails decodeSensitiveDetails(byte[] array, KeyParameterWrapper keyParameterWrapper) throws IOException, SecretKeyExpiredException {
        byte[] decryptedContent = decrypter.decryptBytes(keyParameterWrapper, array);
        return objectConverter.fromByteArray(decryptedContent, SensitiveDetails.class);
    }

}
