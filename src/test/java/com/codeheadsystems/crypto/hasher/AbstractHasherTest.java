package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;

import org.junit.Test;

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;

/**
 * BSD-Style License 2016
 */
public abstract class AbstractHasherTest {

    protected HasherBuilder hasherBuilder;
    protected String testWord;

    @Test
    public void testStandardUsage() {
        Hasher hasher = hasherBuilder.build();

        byte[] hashedValue = hasher.generateHash(testWord);
        assertTrue(hasher.isSame(hashedValue, testWord));
        assertFalse(hasher.isSame(hashedValue, testWord + "x"));
    }

    @Test(expected = HasherException.class)
    public void testBadDigest() {
        Hasher hasher = hasherBuilder.digest("JUNKY").build();
        hasher.generateHash(testWord);
    }

    @Test
    public void testSaltSizeChangeFailure() {
        Hasher hasher1 = hasherBuilder.saltSize(3).build();
        Hasher hasher2 = hasherBuilder.saltSize(2).build();

        hashersShouldBehaveDifferently(hasher1, hasher2);
    }

    @Test
    public void testIterationsChangeFailure() {
        Hasher hasher1 = hasherBuilder.iterations(300).build();
        Hasher hasher2 = hasherBuilder.iterations(200).build();

        hashersShouldBehaveDifferently(hasher1, hasher2);
    }

    protected void hashersShouldBehaveDifferently(Hasher hasher1, Hasher hasher2) {
        byte[] hashedValue = hasher1.generateHash(testWord);
        assertTrue(hasher1.isSame(hashedValue, testWord));
        assertFalse(hasher2.isSame(hashedValue, testWord));

        hashedValue = hasher2.generateHash(testWord);
        assertTrue(hasher2.isSame(hashedValue, testWord));
        assertFalse(hasher1.isSame(hashedValue, testWord));
    }
}
