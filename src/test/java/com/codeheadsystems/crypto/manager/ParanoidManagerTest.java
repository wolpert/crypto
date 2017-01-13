package com.codeheadsystems.crypto.manager;

import com.codeheadsystems.crypto.CryptoException;
import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;
import com.codeheadsystems.crypto.random.UnsecureRandomProvider;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static com.codeheadsystems.crypto.Utilities.getCharset;
import static com.codeheadsystems.crypto.Utilities.getUuid;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertFalse;

/**
 * BSD-Style License 2016
 */
public class ParanoidManagerTest {

    private Manager manager;
    private KeyParameterWrapper keyParameterWrapper;

    @Before
    public void setRandomFactory() {
        Utilities.setRandomProvider(new UnsecureRandomProvider());
    }

    @Before
    public void init() throws ParanoidManagerException {
        manager = new ParanoidManager();
        keyParameterWrapper = new KeyParameterWrapper(manager.generateRandomAesKey());
    }

    @Test
    public void testSensitiveDetails() throws IOException, SecretKeyExpiredException, CryptoException {
        String id1 = getUuid();
        SecondaryKey secondaryKey = new SecondaryKey(keyParameterWrapper, null, null);
        byte[] bytes = manager.encode(id1, secondaryKey);
        String id2 = manager.decode(bytes, secondaryKey);

        assertEquals(id1, id2);
        assertFalse(id1.equals(new String(bytes, getCharset())));
    }

    @Test(expected = CryptoException.class)
    public void testEncodeFailure() throws IOException, SecretKeyExpiredException, CryptoException {
        String id1 = getUuid();
        SecondaryKey secondaryKey = new SecondaryKey(keyParameterWrapper, null, null);
        byte[] bytes = manager.encode(id1, secondaryKey);
        byte b = bytes[bytes.length - 1];
        b = (b == Byte.MAX_VALUE ? Byte.MIN_VALUE : Byte.MAX_VALUE);
        bytes[bytes.length - 1] = b;
        manager.decode(bytes, secondaryKey);
    }

    @Test
    public void testKeyManagement() throws SecretKeyExpiredException, CryptoException {
        String password = "password";
        SecondaryKey secondary = manager.generateFreshSecondary(password);
        byte[] salt = secondary.getSalt();
        assertNotNull(secondary.getEncryptedKey());
        assertNotNull(secondary.getKeyParameterWrapper());
        byte[] k1 = secondary.getKeyParameterWrapper().getKeyParameter().getKey();
        assertNotNull(k1);

        SecondaryKey redo = manager.regenerateSecondary(password, salt, secondary.getEncryptedKey());
        byte[] ek1 = secondary.getEncryptedKey();
        byte[] ek2 = redo.getEncryptedKey();
        assertEqualByteArrays(ek1, ek2);
        byte[] k2 = redo.getKeyParameterWrapper().getKeyParameter().getKey();
        assertEqualByteArrays(k1, k2);

        SecondaryKey newSecondary = manager.generateFreshSecondary(redo);
        SecondaryKey redoNewSecondary = manager.regenerateSecondary(redo, newSecondary.getEncryptedKey());
        assertEqualByteArrays(newSecondary.getEncryptedKey(), redoNewSecondary.getEncryptedKey());
    }

    @Test
    public void testDefaultUseCase() throws CryptoException, SecretKeyExpiredException, IOException {
        String password = "password";
        String clearText = "this is NOT a test";

        SecondaryKey key = manager.generateFreshSecondary(password);
        byte[] encryptedkey = key.getEncryptedKey();
        byte[] salt = key.getSalt();
        assertEquals(32, salt.length);
        byte[] encryptedText = manager.encode(clearText, key);

        key = manager.regenerateSecondary(password, salt, encryptedkey);
        String decodedText = manager.decode(encryptedText, key);

        assertEquals(clearText, decodedText);
    }

    public void assertEqualByteArrays(byte[] b1, byte[] b2) {
        assertNotNull(b1);
        assertNotNull(b2);
        assertEquals(b1.length, b2.length);
        for (int i = 0; i < b1.length; i++) {
            assertEquals(b1[i], b2[i]);
        }
    }
}
