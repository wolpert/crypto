package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.random.SecureRandomProvider;
import com.codeheadsystems.crypto.random.UnsecureRandomProvider;

import org.junit.Before;
import org.junit.Test;

import static com.codeheadsystems.crypto.Utilities.add;
import static com.codeheadsystems.crypto.Utilities.randomBytes;
import static junit.framework.TestCase.assertEquals;

/**
 * BSD-Style License 2016
 */
public class UtilitiesTest {

    @Before
    public void setRandomFactory() {
        Utilities.setRandomProvider(new UnsecureRandomProvider());
    }

    @Test
    public void checkForFailureInResettingRandomProvider() {
        Utilities.setRandomProvider(new SecureRandomProvider());
        assertEquals(UnsecureRandomProvider.class, Utilities.getRandomProvider().getClass()); // Already set once via the before.
        assertEquals(false, Utilities.isSecureRandomProvider());
    }

    @Test
    public void testAddWorks() {
        byte[] a1 = {0, 1, 2};
        byte[] a2 = {5, 6};
        byte[] result = add(a1, a2);
        assertEquals(result[0], a1[0]);
        assertEquals(result[1], a1[1]);
        assertEquals(result[2], a1[2]);
        assertEquals(result[3], a2[0]);
        assertEquals(result[4], a2[1]);
    }

    @Test
    public void testGetRandomBites() {
        byte[] array = randomBytes(10);
        assertEquals(10, array.length);
    }
}
