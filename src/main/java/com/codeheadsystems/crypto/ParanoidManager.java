package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.cipher.ParanoidDecrypter;
import com.codeheadsystems.crypto.cipher.ParanoidEncrypter;
import com.codeheadsystems.crypto.password.KeyParameterFactory;
import com.codeheadsystems.crypto.password.ParanoidKeyParameterFactory;
import com.codeheadsystems.crypto.timer.DefaultTimerProvider;
import com.codeheadsystems.crypto.timer.TimerProvider;

/**
 * Effectively a facade around the paranoid facilities
 * <p/>
 * BSD-Style License 2016
 */
public class ParanoidManager {

    private final TimerProvider timerProvider;
    private final KeyParameterFactory shortTermKeyParameterFactory; // used for short-lived passwords decoding
    private final KeyParameterFactory longTermKeyParameterFactory; // used for the longer term password file
    private final Encrypter encrypter;
    private final Decrypter decrypter;

    public ParanoidManager() throws ParanoidException {
        if (!Utilities.isSecureRandomProvider()) {
            throw new ParanoidException("Paranoid Manager will not operate without SecureRandom provider");
        }
        timerProvider = new DefaultTimerProvider();
        encrypter = new ParanoidEncrypter();
        decrypter = new ParanoidDecrypter();
        KeyParameterFactory.AbstractKeyParameterFactoryBuilder builder = new ParanoidKeyParameterFactory.Builder();
        builder.timerProvider(timerProvider).iterationCount((int) Math.pow(2, 20));
        shortTermKeyParameterFactory = builder.expirationInMills(1000).build(); // 1 second
        longTermKeyParameterFactory = builder.expirationInMills(10 * 60 * 1000).build(); // 10 mins
    }

}
