package com.codeheadsystems.crypto.hasher;

import org.junit.Test;

import java.nio.charset.Charset;

import static junit.framework.TestCase.assertEquals;

/**
 * BSD-Style License 2016
 */
public class StandardHasherImplTest {

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

}
