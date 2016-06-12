package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;

import org.junit.Before;
import org.junit.Test;

import static junit.framework.TestCase.assertTrue;

/**
 * BSD-Style License 2016
 */
public class OWASPHashImplTest extends AbstractHasherTest {

    @Before
    public void createDefaultObjects() {
        hasherBuilder = new HasherBuilder().digest("PBKDF2WithHmacSHA512");
        testWord = "This is a test";
    }

    @Test
    public void testAlgoChangeFailure() {
        Hasher hasher1 = hasherBuilder.digest("PBKDF2WithHmacSHA512").build();
        Hasher hasher2 = hasherBuilder.digest("PBKDF2WithHmacSHA1").build();

        hashersShouldBehaveDifferently(hasher1, hasher2);
    }

    @Test
    public void testKeySizeChangeFailure() {
        Hasher hasher1 = hasherBuilder.keySize(256).build();
        Hasher hasher2 = hasherBuilder.keySize(251).build();

        hashersShouldBehaveDifferently(hasher1, hasher2);
    }


    @Test
    public void testCharsetChangeDoesNotFail() {
        Hasher hasher1 = hasherBuilder.charSet("UTF-8").build();
        Hasher hasher2 = hasherBuilder.charSet("UTF-16LE").build();

        byte[] hashedValue = hasher1.generateHash(testWord);
        assertTrue(hasher1.isSame(hashedValue, testWord));
        assertTrue(hasher2.isSame(hashedValue, testWord));
    }


}
