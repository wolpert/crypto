package com.codeheadsystems.crypto.cipher;

import com.codeheadsystems.shash.impl.RandomProvider;
import org.junit.Test;

import java.util.Random;

import static com.codeheadsystems.crypto.cipher.CipherProvider.KEY_BYTE_SIZE;
import static junit.framework.TestCase.assertEquals;

/**
 * Created by wolpert on 7/19/16.
 */
public class EncryptedByteHolderTest {

    @Test
    public void testTextRoundTrip() {
        RandomProvider randomProvider = RandomProvider.generate(Random::new);
        byte[] iv = randomProvider.getRandomBytes(KEY_BYTE_SIZE);
        byte[] encryptedBytes = randomProvider.getRandomBytes(102);
        EncryptedByteHolder encryptedByteHolder = new EncryptedByteHolder(encryptedBytes, iv);
        String output = encryptedByteHolder.toString();
        System.out.print(output);
        EncryptedByteHolder undo = EncryptedByteHolder.fromString(output);
        assertEquals(true, isEquals(iv, undo.getIv()));
        assertEquals(true, isEquals(encryptedBytes, undo.getEncryptedBytes()));
    }

    public boolean isEquals(byte[] a1, byte[] a2) {
        if (a1.length != a2.length) {
            return false;
        }
        for (int i = 0; i < a1.length; i++) {
            if (a1[i] != a2[i]) {
                return false;
            }
        }
        return true;
    }
}
