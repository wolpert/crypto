package com.codeheadsystems.crypto.cipher;

import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.types.ExceptionFunction;

import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.codeheadsystems.crypto.Utilities.randomBytes;

/**
 * BSD-Style License 2016
 */
public class CipherProvider {

    public final static int KEY_BYTE_SIZE = 32;
    private final static Logger logger = LoggerFactory.getLogger(CipherProvider.class);

    public static byte[] getRandomIV() {
        return randomBytes(KEY_BYTE_SIZE);
    }

    public static byte[] getSalt() {
        return randomBytes(KEY_BYTE_SIZE);
    }

    private ThreadLocal<AEADBlockCipher> aeadBlockCipherThreadLocal = ThreadLocal.withInitial(() -> {
        logger.debug("initCipher();");
        AESFastEngine aesFastEngine = new AESFastEngine();
        return new GCMBlockCipher(aesFastEngine);
    });

    /**
     * This will make sure the cipher is unique per thread. Everytime this is called
     * the cipher itself is reset.
     *
     * @return a cipher usable for AES/GCM/NoPadding.... usable for 256 encoding
     */
    AEADBlockCipher getCipher() {
        logger.debug("getCipher()");
        AEADBlockCipher cipher = aeadBlockCipherThreadLocal.get();
        cipher.reset();
        return cipher;
    }

    /**
     * Preferred method to work on the cipher itself. If the cipher is ever pooled instead of
     * used in a thread-local way, this would make sense.
     *
     * @param function that does the work.
     * @param <R> Return type
     * @param <E> Possible Exception.
     * @return An instance of what R was
     * @throws E some exception that could be thrown in the clause
     */
    public <R, E extends Exception> R callWithCipher(ExceptionFunction<AEADBlockCipher, R, E> function) throws E {
        return function.apply(getCipher());
    }

}
