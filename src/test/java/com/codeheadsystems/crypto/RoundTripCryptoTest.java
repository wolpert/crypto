package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.cipher.EncryptedByteHolder;
import com.codeheadsystems.crypto.cipher.ParanoidDecrypter;
import com.codeheadsystems.crypto.cipher.ParanoidEncrypter;
import com.codeheadsystems.crypto.password.KeyParameterFactory;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;

import org.junit.Test;

import static com.codeheadsystems.crypto.Utilities.getCharset;
import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 * BSD-Style License 2016
 */
public class RoundTripCryptoTest {

    @Test
    public void testRoundTrip() throws SecretKeyExpiredException {
        String password = "lkfdsaf0oudsajhklfdsaf7ds0af7uaoshfkldsf9s67yfihsdka";
        String clearText = "This is not a test... wait... it is...";
        KeyParameterFactory keyParameterFactory = new KeyParameterFactory();
        KeyParameterWrapper encryptKeyParameterWrapper = keyParameterFactory.generate(password);
        Encrypter encrypter = new ParanoidEncrypter(encryptKeyParameterWrapper);
        EncryptedByteHolder encryptBytes = encrypter.encryptBytes(clearText);
        assertNotEquals(clearText, new String(encryptBytes.getEncryptedBytes(), getCharset()));
        byte[] salt = encryptKeyParameterWrapper.getSalt();

        // rebuild the keyParams
        Decrypter decrypter = new ParanoidDecrypter(keyParameterFactory.generate(password, salt));
        String decryptedText = decrypter.decryptText(encryptBytes);
        assertEquals(clearText.length(), decryptedText.length());
        assertEquals(clearText, decryptedText);
    }

    @Test
    public void testRoundTripSaltAsString() throws SecretKeyExpiredException {
        String password = "lkfdsaf0oudsajhklfdsaf7ds0af7uaoshfkldsf9s67yfihsdka";
        String clearText = "This is not a test... wait... it is...";
        KeyParameterFactory keyParameterFactory = new KeyParameterFactory();
        KeyParameterWrapper encryptKeyParameterWrapper = keyParameterFactory.generate(password);
        Encrypter encrypter = new ParanoidEncrypter(encryptKeyParameterWrapper);
        EncryptedByteHolder encryptBytes = encrypter.encryptBytes(clearText);
        assertNotEquals(clearText, new String(encryptBytes.getEncryptedBytes(), getCharset()));
        String salt = encryptKeyParameterWrapper.getSaltAsString();

        // rebuild the keyParams
        Decrypter decrypter = new ParanoidDecrypter(keyParameterFactory.generate(password, salt));
        String decryptedText = decrypter.decryptText(encryptBytes);
        assertEquals(clearText.length(), decryptedText.length());
        assertEquals(clearText, decryptedText);
    }

    @Test(expected = SecretKeyExpiredException.class)
    public void testRoundTripFailureFromExpiredPassword() throws SecretKeyExpiredException {
        String password = "lkfdsaf0oudsajhklfdsaf7ds0af7uaoshfkldsf9s67yfihsdka";
        String clearText = "This is not a test... wait... it is...";
        KeyParameterFactory keyParameterFactory = new KeyParameterFactory();
        KeyParameterWrapper encryptKeyParameterWrapper = keyParameterFactory.generate(password);
        Encrypter encrypter = new ParanoidEncrypter(encryptKeyParameterWrapper);
        EncryptedByteHolder encryptBytes = encrypter.encryptBytes(clearText);
        assertNotEquals(clearText, new String(encryptBytes.getEncryptedBytes(), getCharset()));
        byte[] salt = encryptKeyParameterWrapper.getSalt();

        encryptKeyParameterWrapper.expire();

        // rebuild the keyParams
        Decrypter decrypter = new ParanoidDecrypter(encryptKeyParameterWrapper);
        decrypter.decryptText(encryptBytes);
    }

    @Test(expected = CryptoException.class)
    public void testRoundTripFailureViaIterationCount() throws SecretKeyExpiredException {
        String password = "lkfdsaf0oudsajhklfdsaf7ds0af7uaoshfkldsf9s67yfihsdka";
        String clearText = "This is not a test... wait... it is...";
        KeyParameterFactory keyParameterFactory = new KeyParameterFactory();
        KeyParameterWrapper encryptKeyParameterWrapper = keyParameterFactory.generate(password);
        Encrypter encrypter = new ParanoidEncrypter(encryptKeyParameterWrapper);
        EncryptedByteHolder encryptBytes = encrypter.encryptBytes(clearText);
        assertNotEquals(clearText, new String(encryptBytes.getEncryptedBytes(), getCharset()));
        byte[] salt = encryptKeyParameterWrapper.getSalt();

        keyParameterFactory = new KeyParameterFactory(500);

        // rebuild the keyParams
        Decrypter decrypter = new ParanoidDecrypter(keyParameterFactory.generate(password, salt));
        decrypter.decryptText(encryptBytes);
    }
}
