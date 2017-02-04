package com.codeheadsystems.crypto.cipher;

import com.codeheadsystems.shash.impl.RandomProvider;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.Before;
import org.junit.Test;

import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.Executors;

import static com.codeheadsystems.crypto.Utilities.isSame;
import static com.codeheadsystems.crypto.cipher.CipherProvider.KEY_BYTE_SIZE;
import static java.lang.System.arraycopy;
import static junit.framework.TestCase.*;

/**
 * BSD-Style License 2017
 */

public class CipherProviderTest {

    private CipherProvider cipherProvider;
    private RandomProvider randomProvider;

    @Before
    public void setCipherProvider() {
        cipherProvider = new CipherProvider();
    }

    @Before
    public void setRandomProvider() {
        randomProvider = RandomProvider.generate(Random::new);
    }

    @Test
    public void checkRandomIVSize() {
        assertEquals(32, KEY_BYTE_SIZE);
    }

    @Test
    public void testCipherSameForCurrentThreadWhenCalledTwice() {
        AEADBlockCipher cipher1 = cipherProvider.getCipher();
        AEADBlockCipher cipher2 = cipherProvider.getCipher();

        assertNotNull(cipher1);
        assertNotNull(cipher2);
        assertSame(cipher1, cipher2);
    }

    @Test
    public void testCipherDifferentForDifferentThreads() throws ExecutionException, InterruptedException {
        AEADBlockCipher cipher1 = cipherProvider.getCipher();
        Executor ex = Executors.newCachedThreadPool();
        ExecutorCompletionService<AEADBlockCipher> otherThreadSerice = new ExecutorCompletionService<>(ex);
        AEADBlockCipher cipher2 = otherThreadSerice.submit(() -> cipherProvider.getCipher()).get();

        assertNotNull(cipher1);
        assertNotNull(cipher2);
        assertNotSame(cipher1, cipher2);
    }

    @Test
    public void testCipherWorksWith256BitKeys() throws InvalidCipherTextException {
        AEADBlockCipher cipher = cipherProvider.getCipher();
        Random random = new Random();
        byte[] clearBytes = new byte[1025]; // Requires weird number of bytes
        random.nextBytes(clearBytes);
        byte[] key = new byte[KEY_BYTE_SIZE];
        random.nextBytes(key);
        byte[] iv = randomProvider.getRandomBytes(KEY_BYTE_SIZE);
        assertEquals(32, iv.length); // 256 bits
        assertEquals(32, key.length); // 256 bits

        // Encrypt without an exception... all we care about
        KeyParameter keyParameter = new KeyParameter(key);
        ParametersWithIV keyWithIv = new ParametersWithIV(keyParameter, iv);
        cipher.init(true, keyWithIv);
        byte[] encryptedBytes = new byte[cipher.getOutputSize(clearBytes.length)];
        int length1 = cipher.processBytes(clearBytes, 0, clearBytes.length, encryptedBytes, 0);
        int length2 = cipher.doFinal(encryptedBytes, length1);
        // no padding and mac check
        assertEquals(1025 + 16, length1 + length2);
        byte[] finalBytes = new byte[length1 + length2];
        arraycopy(encryptedBytes, 0, finalBytes, 0, length1 + length2); // Could be longer...

        assertFalse(isSame(clearBytes, finalBytes));

        // undo...
        cipher = cipherProvider.getCipher();
        keyParameter = new KeyParameter(key);
        keyWithIv = new ParametersWithIV(keyParameter, iv);
        cipher.init(false, keyWithIv);
        byte[] decryptedBytes = new byte[cipher.getOutputSize(finalBytes.length)];
        length1 = cipher.processBytes(finalBytes, 0, finalBytes.length, decryptedBytes, 0);
        length2 = cipher.doFinal(decryptedBytes, length1);
        finalBytes = new byte[length1 + length2];
        arraycopy(decryptedBytes, 0, finalBytes, 0, length1 + length2);

        assertTrue(isSame(clearBytes, finalBytes));
    }
}
