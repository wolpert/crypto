package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.random.UnsecureRandomProvider;
import com.codeheadsystems.crypto.timer.DefaultTimerProvider;
import com.codeheadsystems.crypto.timer.TimerProvider;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;

/**
 * BSD-Style License 2016
 */
public class StandardExpirationHandlerTest {

    public static final String PASSWORD = "lkfdsaf0oudsajhklfdsaf7ds0af7uaoshfkldsf9s67yfihsdka";
    private TimerProvider timerProvider = new DefaultTimerProvider();

    @Before
    public void setRandomFactory() {
        Utilities.setRandomProvider(new UnsecureRandomProvider());
    }

    @Test
    public void testFullExpiration() throws SecretKeyExpiredException, InterruptedException {
        KeyParameterFactory keyParameterFactory = new MessageDigestKeyParameterFactory.Builder()
                .timerProvider(timerProvider)
                .expirationInMills(500)
                .build();
        KeyParameterWrapper keyParameterWrapper = keyParameterFactory.generate(PASSWORD); // no salt
        assertNotNull(keyParameterWrapper.getKeyParameter());
        assertNotNull(keyParameterWrapper.getSalt());
        Thread.sleep(500);
        try {
            keyParameterWrapper.getKeyParameter();
            throw new IllegalStateException("We should not have gotten here");
        } catch (SecretKeyExpiredException see) {
            ; // we expect this
        }
    }

    @Test
    public void testDidNotExpire() throws SecretKeyExpiredException {
        KeyParameterFactory keyParameterFactory = new MessageDigestKeyParameterFactory.Builder()
                .timerProvider(timerProvider)
                .expirationInMills(500)
                .build();
        KeyParameterWrapper keyParameterWrapper = keyParameterFactory.generate(PASSWORD); // no salt
        assertNotNull(keyParameterWrapper.getKeyParameter());
    }

    @Test
    public void testDidNotExpireWithNoTime() throws SecretKeyExpiredException {
        KeyParameterFactory keyParameterFactory = new MessageDigestKeyParameterFactory.Builder()
                .timerProvider(timerProvider)
                .expirationInMills(0)
                .build();
        KeyParameterWrapper keyParameterWrapper = keyParameterFactory.generate(PASSWORD); // no salt
        assertNotNull(keyParameterWrapper.getKeyParameter());
    }

    @Test(expected = SecretKeyExpiredException.class)
    public void testDidExpire() throws SecretKeyExpiredException, InterruptedException {
        KeyParameterFactory keyParameterFactory = new MessageDigestKeyParameterFactory.Builder()
                .timerProvider(timerProvider)
                .expirationInMills(50)
                .build();
        KeyParameterWrapper keyParameterWrapper = keyParameterFactory.generate(PASSWORD); // no salt
        Thread.sleep(100);
        assertNotNull(keyParameterWrapper.getKeyParameter());
    }

}
