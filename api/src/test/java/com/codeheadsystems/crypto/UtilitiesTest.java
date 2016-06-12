package com.codeheadsystems.crypto;

import org.junit.Test;

import static junit.framework.TestCase.assertEquals;

/**
 * BSD-Style License 2016
 */
public class UtilitiesTest {

    @Test
    public void testAddWorks() {
        byte[] a1 = {0, 1, 2};
        byte[] a2 = {5, 6};
        byte[] result = Utilities.add(a1, a2);
        assertEquals(result[0], a1[0]);
        assertEquals(result[1], a1[1]);
        assertEquals(result[2], a1[2]);
        assertEquals(result[3], a2[0]);
        assertEquals(result[4], a2[1]);
    }

    @Test
    public void testGetRandomBites() {
        byte[] array = Utilities.randomBytes(10);
        assertEquals(10, array.length);
    }
}
