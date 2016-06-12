package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;

import org.junit.Before;
import org.junit.Test;

import java.nio.charset.Charset;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;

/**
 * BSD-Style License 2016
 */
public class StandardHasherImplTest extends AbstractHasherTest {

    @Before
    public void createDefaultObjects() {
        hasherBuilder = new HasherBuilder();
        testWord = "This is a test";
    }

    @Test
    public void testImplSaltWorks() {
        StandardHasherImpl hasher = new StandardHasherImpl("MD5", 2, 1, Charset.defaultCharset());

        byte[] hashedValue = hasher.generateHash("This is NOT a test");
        byte[] salt = hasher.getSalt(hashedValue);
        assertEquals(salt[0], hashedValue[0]);
        assertEquals(salt[1], hashedValue[1]);
        salt = hasher.getSalt(hashedValue);
        assertEquals(salt[0], hashedValue[0]);
        assertEquals(salt[1], hashedValue[1]);
        hasher.isSame(salt, hasher.getSalt(hashedValue));
    }

    @Test
    public void testAlgoChangeFailure() {
        Hasher hasher1 = hasherBuilder.digest("SHA-256").build();
        Hasher hasher2 = hasherBuilder.digest("SHA-512").build();

        hashersShouldBehaveDifferently(hasher1, hasher2);
    }

    @Test
    public void testNoSaltStillWorks() {
        Hasher hasher = hasherBuilder.saltSize(0).build();

        byte[] hashedValue = hasher.generateHash(testWord);
        assertTrue(hasher.isSame(hashedValue, testWord));
        assertFalse(hasher.isSame(hashedValue, testWord + "x"));
    }

    @Test
    public void testCharsetChangeFailure() {
        Hasher hasher1 = hasherBuilder.charSet("UTF-8").build();
        Hasher hasher2 = hasherBuilder.charSet("UTF-16LE").build();

        hashersShouldBehaveDifferently(hasher1, hasher2);
    }

}
