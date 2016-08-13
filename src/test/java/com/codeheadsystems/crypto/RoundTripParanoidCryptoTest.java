package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.cipher.EncryptedByteHolder;
import com.codeheadsystems.crypto.cipher.ParanoidDecrypter;
import com.codeheadsystems.crypto.cipher.ParanoidEncrypter;
import com.codeheadsystems.crypto.password.KeyParameterFactory;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.ParanoidKeyParameterFactory;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;
import com.codeheadsystems.crypto.random.UnsecureRandomProvider;
import com.codeheadsystems.crypto.timer.DefaultTimerProvider;
import com.codeheadsystems.crypto.timer.TimerProvider;

import org.junit.Before;
import org.junit.Test;

import static com.codeheadsystems.crypto.Utilities.getCharset;
import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 * BSD-Style License 2016
 */
public class RoundTripParanoidCryptoTest {

    public static final String PASSWORD = "lkfdsaf0oudsajhklfdsaf7ds0af7uaoshfkldsf9s67yfihsdka";
    public static final String CLEAR_TEXT = "This is not a test... wait... it is...";
    private KeyParameterFactory paranoidKeyParameterFactory;
    private TimerProvider timerProvider = new DefaultTimerProvider();

    @Before
    public void setRandomFactory() {
        Utilities.setRandomProvider(new UnsecureRandomProvider());
    }

    @Before
    public void createKeyParameterFactory() {
        paranoidKeyParameterFactory = new ParanoidKeyParameterFactory.Builder().timerProvider(timerProvider).iterationCount((int) Math.pow(2, 14)).build();
    }

    protected KeyParameterWrapper generate(byte[] salt) {
        if (salt != null) {
            return paranoidKeyParameterFactory.generate(PASSWORD, salt);
        } else {
            return paranoidKeyParameterFactory.generate(PASSWORD);
        }
    }

    @Test
    public void testClassType() {
        assert paranoidKeyParameterFactory instanceof ParanoidKeyParameterFactory;
    }

    @Test
    public void testRoundTrip() throws SecretKeyExpiredException {
        // This test is slow because its using the defaults
        KeyParameterFactory slowDefaultFactory = new ParanoidKeyParameterFactory.Builder().timerProvider(timerProvider).build();
        KeyParameterWrapper encryptKeyParameterWrapper = slowDefaultFactory.generate(PASSWORD);
        byte[] salt = encryptKeyParameterWrapper.getSalt();
        assertEquals(256 / 8, encryptKeyParameterWrapper.getKeyParameter().getKey().length);
        assertEquals(128 / 8, salt.length);
        EncryptedByteHolder encryptBytes = getEncryptedByteHolder(encryptKeyParameterWrapper);

        // rebuild the keyParams
        Decrypter decrypter = new ParanoidDecrypter(slowDefaultFactory.generate(PASSWORD, salt));
        String decryptedText = decrypter.decryptText(encryptBytes);
        assertEquals(CLEAR_TEXT.length(), decryptedText.length());
        assertEquals(CLEAR_TEXT, decryptedText);
    }

    private EncryptedByteHolder getEncryptedByteHolder(KeyParameterWrapper encryptKeyParameterWrapper) throws SecretKeyExpiredException {
        Encrypter encrypter = new ParanoidEncrypter(encryptKeyParameterWrapper);
        EncryptedByteHolder encryptBytes = encrypter.encryptBytes(CLEAR_TEXT);
        assertNotEquals(CLEAR_TEXT, new String(encryptBytes.getEncryptedBytes(), getCharset()));
        return encryptBytes;
    }

    @Test
    public void testRoundTripSaltAsString() throws SecretKeyExpiredException {
        KeyParameterWrapper encryptKeyParameterWrapper = generate(null);
        String salt = encryptKeyParameterWrapper.getSaltAsString();
        EncryptedByteHolder encryptBytes = getEncryptedByteHolder(encryptKeyParameterWrapper);

        // rebuild the keyParams
        Decrypter decrypter = new ParanoidDecrypter(paranoidKeyParameterFactory.generate(PASSWORD, salt));
        String decryptedText = decrypter.decryptText(encryptBytes);
        assertEquals(CLEAR_TEXT.length(), decryptedText.length());
        assertEquals(CLEAR_TEXT, decryptedText);
    }

    @Test(expected = SecretKeyExpiredException.class)
    public void testRoundTripFailureFromExpiredPassword() throws SecretKeyExpiredException {
        KeyParameterWrapper encryptKeyParameterWrapper = generate(null);
        EncryptedByteHolder encryptBytes = getEncryptedByteHolder(encryptKeyParameterWrapper);

        encryptKeyParameterWrapper.expire();

        // rebuild the keyParams
        Decrypter decrypter = new ParanoidDecrypter(encryptKeyParameterWrapper);
        decrypter.decryptText(encryptBytes);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidIterationCount() throws SecretKeyExpiredException {
        KeyParameterWrapper encryptKeyParameterWrapper = generate(null);
        byte[] salt = encryptKeyParameterWrapper.getSalt();
        EncryptedByteHolder encryptBytes = getEncryptedByteHolder(encryptKeyParameterWrapper);

        // rebuild the keyParams
        new ParanoidDecrypter(new ParanoidKeyParameterFactory.Builder().iterationCount(500).build().generate(PASSWORD, salt));
    }

    @Test(expected = CryptoException.class)
    public void testRoundTripFailureViaIterationCount() throws SecretKeyExpiredException {
        KeyParameterWrapper encryptKeyParameterWrapper = generate(null);
        byte[] salt = encryptKeyParameterWrapper.getSalt();
        EncryptedByteHolder encryptBytes = getEncryptedByteHolder(encryptKeyParameterWrapper);
        // rebuild the keyParams
        Decrypter decrypter = new ParanoidDecrypter(new ParanoidKeyParameterFactory.Builder().timerProvider(timerProvider).iterationCount((int) Math.pow(2, 15)).build().generate(PASSWORD, salt));
        decrypter.decryptText(encryptBytes);
    }
}
