package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.cipher.CipherProvider;
import com.codeheadsystems.shash.impl.RandomProvider;
import org.junit.Test;

import java.util.Random;

import static org.junit.Assert.assertNotNull;

/**
 * BSD-Style License 2016
 */
public class StandardExpirationHandlerTest {

    public static final String PASSWORD = "lkfdsaf0oudsajhklfdsaf7ds0af7uaoshfkldsf9s67yfihsdka";

    private RandomProvider randomProvider = RandomProvider.generate(Random::new);

    @Test
    public void testFullExpiration() throws SecretKeyExpiredException, InterruptedException {
        KeyParameterFactory keyParameterFactory = new KeyParameterFactory.Builder()
                .iterationCount(16384)
                .expirationInMills(400)
                .randomProvider(randomProvider)
                .build();
        byte[] salt = randomProvider.getRandomBytes(CipherProvider.KEY_BYTE_SIZE);
        KeyParameterWrapper keyParameterWrapper = keyParameterFactory.generate(PASSWORD, salt);
        assertNotNull(keyParameterWrapper.getKey());
        Thread.sleep(500);
        try {
            keyParameterWrapper.getKey();
            throw new IllegalStateException("We should not have gotten here");
        } catch (SecretKeyExpiredException see) {
            ; // we expect this
        }
    }

    @Test
    public void testDidNotExpire() throws SecretKeyExpiredException {
        KeyParameterFactory keyParameterFactory = new KeyParameterFactory.Builder()
                .iterationCount(16384)
                .expirationInMills(500)
                .randomProvider(randomProvider)
                .build();
        byte[] salt = randomProvider.getRandomBytes(CipherProvider.KEY_BYTE_SIZE);
        KeyParameterWrapper keyParameterWrapper = keyParameterFactory.generate(PASSWORD, salt);
        assertNotNull(keyParameterWrapper.getKey());
    }

    @Test
    public void testDidNotExpireWithNoTime() throws SecretKeyExpiredException {
        KeyParameterFactory keyParameterFactory = new KeyParameterFactory.Builder()
                .iterationCount(16384)
                .expirationInMills(0)
                .randomProvider(randomProvider)
                .build();
        byte[] salt = randomProvider.getRandomBytes(CipherProvider.KEY_BYTE_SIZE);
        KeyParameterWrapper keyParameterWrapper = keyParameterFactory.generate(PASSWORD, salt); // no salt
        assertNotNull(keyParameterWrapper.getKey());
    }

    @Test(expected = SecretKeyExpiredException.class)
    public void testDidExpire() throws SecretKeyExpiredException, InterruptedException {
        KeyParameterFactory keyParameterFactory = new KeyParameterFactory.Builder()
                .iterationCount(16384)
                .expirationInMills(50)
                .randomProvider(randomProvider)
                .build();
        byte[] salt = randomProvider.getRandomBytes(CipherProvider.KEY_BYTE_SIZE);
        KeyParameterWrapper keyParameterWrapper = keyParameterFactory.generate(PASSWORD, salt); // no salt
        Thread.sleep(100);
        assertNotNull(keyParameterWrapper.getKey());
    }

}
