package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.cipher.CipherProvider;
import com.codeheadsystems.crypto.cipher.ParanoidDecrypter;
import com.codeheadsystems.crypto.cipher.ParanoidEncrypter;
import com.codeheadsystems.crypto.password.KeyParameterFactory;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;
import com.codeheadsystems.shash.impl.RandomProvider;
import org.junit.Before;
import org.junit.Test;

import java.util.Objects;
import java.util.Random;

import static junit.framework.TestCase.assertEquals;

/**
 * BSD-Style License 2016
 */
public class RoundTripParanoidCryptoTest {

    public static final String PASSWORD = "lkfdsaf0oudsajhklfdsaf7ds0af7uaoshfkldsf9s67yfihsdka";
    public static final String CLEAR_TEXT = "This is not a test... wait... it is...";
    private KeyParameterFactory paranoidKeyParameterFactory;
    private CipherProvider cipherProvider;
    private RandomProvider randomProvider = RandomProvider.generate(Random::new);

    @Before
    public void createKeyParameterFactory() {
        paranoidKeyParameterFactory = new KeyParameterFactory.Builder().iterationCount((int) Math.pow(2, 14)).randomProvider(randomProvider).build();
    }

    @Before
    public void setCipherProvider() {
        cipherProvider = new CipherProvider();
    }

    protected KeyParameterWrapper generate(byte[] salt) {
        return paranoidKeyParameterFactory.generate(PASSWORD, Objects.requireNonNull(salt));
    }

    @Test
    public void testRoundTrip() throws SecretKeyExpiredException, CryptoException {
        // This test is slow because its using the defaults
        KeyParameterFactory slowDefaultFactory = new KeyParameterFactory.Builder().randomProvider(randomProvider).build();
        byte[] salt = randomProvider.getRandomBytes(CipherProvider.KEY_BYTE_SIZE);
        KeyParameterWrapper encryptKeyParameterWrapper = slowDefaultFactory.generate(PASSWORD, salt);
        assertEquals(256 / 8, encryptKeyParameterWrapper.getKey().length);
        assertEquals(256 / 8, salt.length);
        byte[] encryptBytes = getEncryptedByteHolder(encryptKeyParameterWrapper);

        // rebuild the keyParams
        Decrypter decrypter = new ParanoidDecrypter(cipherProvider);
        String decryptedText = decrypter.decryptText(slowDefaultFactory.generate(PASSWORD, salt), encryptBytes);
        assertEquals(CLEAR_TEXT.length(), decryptedText.length());
        assertEquals(CLEAR_TEXT, decryptedText);
    }

    private byte[] getEncryptedByteHolder(KeyParameterWrapper encryptKeyParameterWrapper) throws SecretKeyExpiredException, CryptoException {
        Encrypter encrypter = new ParanoidEncrypter(cipherProvider, randomProvider);
        return encrypter.encryptBytes(encryptKeyParameterWrapper, CLEAR_TEXT);
    }

    @Test
    public void testRoundTripSaltAsString() throws SecretKeyExpiredException, CryptoException {
        byte[] salt = randomProvider.getRandomBytes(CipherProvider.KEY_BYTE_SIZE);
        KeyParameterWrapper encryptKeyParameterWrapper = generate(salt);
        String saltString = Utilities.bytesToString(salt);
        byte[] encryptBytes = getEncryptedByteHolder(encryptKeyParameterWrapper);

        // rebuild the keyParams
        Decrypter decrypter = new ParanoidDecrypter(cipherProvider);
        String decryptedText = decrypter.decryptText(paranoidKeyParameterFactory.generate(PASSWORD, saltString), encryptBytes);
        assertEquals(CLEAR_TEXT.length(), decryptedText.length());
        assertEquals(CLEAR_TEXT, decryptedText);
    }

    @Test(expected = SecretKeyExpiredException.class)
    public void testRoundTripFailureFromExpiredPassword() throws SecretKeyExpiredException, CryptoException {
        byte[] salt = randomProvider.getRandomBytes(CipherProvider.KEY_BYTE_SIZE);
        KeyParameterWrapper encryptKeyParameterWrapper = generate(salt);
        byte[] encryptBytes = getEncryptedByteHolder(encryptKeyParameterWrapper);

        encryptKeyParameterWrapper.expire();

        // rebuild the keyParams
        Decrypter decrypter = new ParanoidDecrypter(cipherProvider);
        decrypter.decryptText(encryptKeyParameterWrapper, encryptBytes);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidIterationCount() throws SecretKeyExpiredException {
        byte[] salt = randomProvider.getRandomBytes(CipherProvider.KEY_BYTE_SIZE);
        // rebuild the keyParams
        new KeyParameterFactory.Builder().iterationCount(500).build().generate(PASSWORD, salt);
    }

    @Test(expected = CryptoException.class)
    public void testRoundTripFailureViaIterationCount() throws SecretKeyExpiredException, CryptoException {
        byte[] salt = randomProvider.getRandomBytes(CipherProvider.KEY_BYTE_SIZE);
        KeyParameterWrapper encryptKeyParameterWrapper = generate(salt);
        byte[] encryptBytes = getEncryptedByteHolder(encryptKeyParameterWrapper);
        // rebuild the keyParams
        Decrypter decrypter = new ParanoidDecrypter(cipherProvider);
        decrypter.decryptText(new KeyParameterFactory.Builder().randomProvider(randomProvider).iterationCount((int) Math.pow(2, 15)).build().generate(PASSWORD, salt), encryptBytes);
    }

    @Test
    public void documentationTest() throws SecretKeyExpiredException, CryptoException {

        // encryption
        String clearText = "Super Important Text";
        KeyParameterFactory factory = new KeyParameterFactory.Builder()
                .expirationInMills(20000) // Expire keys in 20 seconds
                .randomProvider(randomProvider)
                .build();
        String password = "lkfdsaf0oudsajhklfdsaf7ds0af7uaoshfkldsf9s67yfihsdka";
        byte[] salt = randomProvider.getRandomBytes(CipherProvider.KEY_BYTE_SIZE);
        KeyParameterWrapper key = factory.generate(password, salt);
        Encrypter encrypter = new ParanoidEncrypter(cipherProvider, randomProvider);
        byte[] encryptBytes = encrypter.encryptBytes(key, clearText);
        String stringVersionOfEncryptedBytes = Utilities.bytesToString(encryptBytes);

        // decryption
        byte[] encryptedBytes = Utilities.stringToBytes(stringVersionOfEncryptedBytes);
        key = factory.generate(password, salt); // regenerate key if previous one expired
        Decrypter decrypter = new ParanoidDecrypter(cipherProvider);
        String decryptedText = decrypter.decryptText(key, encryptedBytes);

        assertEquals(clearText, decryptedText);
    }
}
