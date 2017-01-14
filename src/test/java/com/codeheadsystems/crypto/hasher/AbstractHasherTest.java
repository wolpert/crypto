package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;
import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.random.UnsecureRandomProvider;

import org.junit.Before;
import org.junit.Test;

import static com.codeheadsystems.crypto.Utilities.isSame;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;

/**
 * BSD-Style License 2016
 */
public abstract class AbstractHasherTest {

    protected HasherBuilder hasherBuilder;
    protected String testWord;

    @Before
    public void setRandomFactory() {
        Utilities.setRandomProvider(new UnsecureRandomProvider());
    }

    @Test
    public void testStandardUsage() {
        Hasher hasher = hasherBuilder.build();

        HashHolder hashedValue = hasher.generateHash(testWord);
        assertTrue(hasher.isSame(hashedValue, testWord));
        assertFalse(hasher.isSame(hashedValue, testWord + "x"));
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
        HashHolder hashedValue1 = hasher1.generateHash(testWord);
        HashHolder hashedValue2 = hasher2.generateHash(testWord);
        assertFalse(isSame(hashedValue1.getHash(), hashedValue2.getHash()));
    }
}
