package com.codeheadsystems.crypto.manager;

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

    private ParanoidManager paranoidManager;
    private KeyParameterWrapper keyParameterWrapper;

    @Before
    public void setRandomFactory() {
        Utilities.setRandomProvider(new UnsecureRandomProvider());
    }

    @Before
    public void init() throws ParanoidManagerException {
        paranoidManager = new ParanoidManager();
        keyParameterWrapper = new KeyParameterWrapper(paranoidManager.generateRandomAesKey());
    }

    @Test
    public void testSensitiveDetails() throws IOException, SecretKeyExpiredException {
        String id1 = getUuid();
        byte[] bytes = paranoidManager.encode(id1, keyParameterWrapper);
        String id2 = paranoidManager.decode(bytes, keyParameterWrapper);

        assertEquals(id1, id2);
        assertFalse(id1.equals(new String(bytes, getCharset())));
    }

    @Test
    public void testKeyManagement() throws SecretKeyExpiredException {
        String password = "password";
        byte[] salt = paranoidManager.freshSalt();
        SecondaryKey secondary = paranoidManager.generateFreshSecondary(password, salt);
        assertNotNull(secondary.getEncryptedKey());
        assertNotNull(secondary.getKeyParameterWrapper());
        byte[] k1 = secondary.getKeyParameterWrapper().getKeyParameter().getKey();
        assertNotNull(k1);

        SecondaryKey redo = paranoidManager.regenerateSecondary(password, salt, secondary.getEncryptedKey());
        byte[] ek1 = secondary.getEncryptedKey();
        byte[] ek2 = redo.getEncryptedKey();
        assertEqualByteArrays(ek1, ek2);
        byte[] k2 = redo.getKeyParameterWrapper().getKeyParameter().getKey();
        assertEqualByteArrays(k1, k2);
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
