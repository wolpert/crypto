package com.codeheadsystems.crypto.manager;

import org.junit.Test;

import java.io.IOException;

import static com.codeheadsystems.crypto.Utilities.getCharset;
import static com.codeheadsystems.crypto.Utilities.getUuid;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertFalse;

/**
 * BSD-Style License 2016
 */
public class ObjectManipulatorTest {

    private ObjectManipulator objectManipulator = new ObjectManipulator();

    @Test
    public void testStandardMovement() throws IOException {
        String startString = "1111111111111122222222222222222222222 Thi sis fd sfa";
        byte[] compressedBytes = objectManipulator.compressString(startString);
        String endString = objectManipulator.uncompressString(compressedBytes);
        assertEquals(startString, endString);
        assertFalse(startString.equals(new String(compressedBytes, getCharset())));
    }

}
