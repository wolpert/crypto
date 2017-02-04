package com.codeheadsystems.crypto;

import com.codeheadsystems.shash.impl.RandomProvider;
import org.junit.Test;

import java.util.Random;

import static com.codeheadsystems.crypto.Utilities.add;
import static junit.framework.TestCase.assertEquals;

/**
 * BSD-Style License 2016
 */
public class UtilitiesTest {

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
        byte[] array = RandomProvider.generate(Random::new).getRandomBytes(10);
        assertEquals(10, array.length);
    }

    @Test
    public void hexConversion() {
        byte[] array = RandomProvider.generate(Random::new).getRandomBytes(200);
        String hexString = Utilities.toHex(array);
        byte[] resultingArray = Utilities.fromHex(hexString);
        for (int i = 0; i < array.length; i++) {
            assertEquals(array[i], resultingArray[i]);
        }
    }
}
