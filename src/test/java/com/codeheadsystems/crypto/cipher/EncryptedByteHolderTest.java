package com.codeheadsystems.crypto.cipher;

import org.junit.Test;

import static com.codeheadsystems.crypto.Utilities.randomBytes;
import static junit.framework.TestCase.assertEquals;

/**
 * Created by wolpert on 7/19/16.
 */
public class EncryptedByteHolderTest {

    @Test
    public void testTextRoundTrip() {
        byte[] iv = randomBytes(16);
        byte[] encryptedBytes = randomBytes(102);
        EncryptedByteHolder encryptedByteHolder = new EncryptedByteHolder(encryptedBytes, iv);
        String output = encryptedByteHolder.toString();
        System.out.print(output);
        EncryptedByteHolder undo = EncryptedByteHolder.fromString(output);
        assertEquals(true, isEquals(iv, undo.getIv()));
        assertEquals(true, isEquals(encryptedBytes, undo.getEncryptedBytes()));
    }

    public boolean isEquals(byte[] a1, byte[]a2) {
        if (a1.length != a2.length) {
            return false;
        }
        for(int i=0; i< a1.length; i++) {
            if (a1[i] != a2[i]) {
                return false;
            }
        }
        return true;
    }
}
