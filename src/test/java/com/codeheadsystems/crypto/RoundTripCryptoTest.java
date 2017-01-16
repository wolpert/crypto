package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.cipher.CipherProvider;
import com.codeheadsystems.crypto.cipher.ParanoidDecrypter;
import com.codeheadsystems.crypto.cipher.ParanoidEncrypter;
import com.codeheadsystems.crypto.password.ExpiringKeyParameterFactory;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;
import com.codeheadsystems.crypto.random.UnsecureRandomProvider;

import org.junit.Before;
import org.junit.Test;

import static java.util.Objects.requireNonNull;
import static junit.framework.TestCase.assertEquals;

/**
 * BSD-Style License 2016
 */
public class RoundTripCryptoTest {

    public static final String PASSWORD = "lkfdsaf0oudsajhklfdsaf7ds0af7uaoshfkldsf9s67yfihsdka";
    public static final String CLEAR_TEXT = "This is not a test... wait... it is...";
    private ExpiringKeyParameterFactory messageDigestExpiringKeyParameterFactory;
    private CipherProvider cipherProvider;

    @Before
    public void setRandomFactory() {
        Utilities.setRandomProvider(new UnsecureRandomProvider());
    }

    @Before
    public void createKeyParameterFactory() {
        messageDigestExpiringKeyParameterFactory = new ExpiringKeyParameterFactory.Builder().iterationCount(16384).build();
    }

    @Before
    public void setCipherProvider() {
        cipherProvider = new CipherProvider();
    }

    protected KeyParameterWrapper generate(byte[] salt) {
        return messageDigestExpiringKeyParameterFactory.generate(PASSWORD, requireNonNull(salt));
    }

    @Test
    public void testRoundTrip() throws SecretKeyExpiredException, CryptoException {
        byte[] salt = CipherProvider.getSalt();
        KeyParameterWrapper encryptKeyParameterWrapper = generate(salt);
        assertEquals(256 / 8, encryptKeyParameterWrapper.getKey().length);
        byte[] encryptBytes = getEncryptedByteHolder(encryptKeyParameterWrapper);

        // rebuild the keyParams
        Decrypter decrypter = new ParanoidDecrypter(cipherProvider);
        String decryptedText = decrypter.decryptText(messageDigestExpiringKeyParameterFactory.generate(PASSWORD, salt), encryptBytes);
        assertEquals(CLEAR_TEXT.length(), decryptedText.length());
        assertEquals(CLEAR_TEXT, decryptedText);
    }

    private byte[] getEncryptedByteHolder(KeyParameterWrapper encryptKeyParameterWrapper) throws SecretKeyExpiredException, CryptoException {
        Encrypter encrypter = new ParanoidEncrypter(cipherProvider);
        return encrypter.encryptBytes(encryptKeyParameterWrapper, CLEAR_TEXT);
    }

    @Test
    public void testRoundTripSaltAsString() throws SecretKeyExpiredException, CryptoException {
        byte[] salt = CipherProvider.getSalt();
        KeyParameterWrapper encryptKeyParameterWrapper = generate(salt);
        String saltString = Utilities.bytesToString(salt);
        byte[] encryptBytes = getEncryptedByteHolder(encryptKeyParameterWrapper);

        // rebuild the keyParams
        Decrypter decrypter = new ParanoidDecrypter(cipherProvider);
        String decryptedText = decrypter.decryptText(messageDigestExpiringKeyParameterFactory.generate(PASSWORD, saltString), encryptBytes);
        assertEquals(CLEAR_TEXT.length(), decryptedText.length());
        assertEquals(CLEAR_TEXT, decryptedText);
    }

    @Test(expected = SecretKeyExpiredException.class)
    public void testRoundTripFailureFromExpiredPassword() throws SecretKeyExpiredException, CryptoException {
        byte[] salt = CipherProvider.getSalt();
        KeyParameterWrapper encryptKeyParameterWrapper = generate(salt);
        byte[] encryptBytes = getEncryptedByteHolder(encryptKeyParameterWrapper);

        encryptKeyParameterWrapper.expire();

        // rebuild the keyParams
        Decrypter decrypter = new ParanoidDecrypter(cipherProvider);
        decrypter.decryptText(encryptKeyParameterWrapper, encryptBytes);
    }

    @Test(expected = CryptoException.class)
    public void testRoundTripFailureViaIterationCount() throws SecretKeyExpiredException, CryptoException {
        byte[] salt = CipherProvider.getSalt();
        KeyParameterWrapper encryptKeyParameterWrapper = generate(salt);
        byte[] encryptBytes = getEncryptedByteHolder(encryptKeyParameterWrapper);

        // rebuild the keyParams
        Decrypter decrypter = new ParanoidDecrypter(cipherProvider);
        decrypter.decryptText(new ExpiringKeyParameterFactory.Builder().iterationCount(16385).build().generate(PASSWORD, salt), encryptBytes);
    }
}
