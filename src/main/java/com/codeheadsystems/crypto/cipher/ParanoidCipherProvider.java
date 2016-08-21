package com.codeheadsystems.crypto.cipher;

import com.codeheadsystems.crypto.password.KeyParameterWrapper;

import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.codeheadsystems.crypto.Utilities.randomBytes;

/**
 * BSD-Style License 2016
 */
public class ParanoidCipherProvider implements CipherProvider {

    private final static Logger logger = LoggerFactory.getLogger(ParanoidCipherProvider.class);
    public final static int BLOCK_LENGTH = 16;

    @Override
    public PaddedBufferedBlockCipher getCipher() {
        logger.debug("getCipher()");
        PKCS7Padding padding = new PKCS7Padding();
        AESFastEngine aesFastEngine = new AESFastEngine();
        SICBlockCipher sicBlockCipher = new SICBlockCipher(aesFastEngine);
        return new PaddedBufferedBlockCipher(sicBlockCipher, padding);
    }

    @Override
    public byte[] getRandomIV() {
        return randomBytes(BLOCK_LENGTH);
    }
}
