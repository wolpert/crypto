package com.codeheadsystems.crypto.cipher;

import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.codeheadsystems.crypto.Utilities.randomBytes;

/**
 * BSD-Style License 2016
 */
public class ParanoidCipherProvider implements CipherProvider {

    public final static int BLOCK_LENGTH = 32;
    private final static Logger logger = LoggerFactory.getLogger(ParanoidCipherProvider.class);

    @Override
    public AEADBlockCipher getCipher() {
        logger.debug("getCipher()");
        AESFastEngine aesFastEngine = new AESFastEngine();
        return new GCMBlockCipher(aesFastEngine);
    }

    @Override
    public byte[] getRandomIV() {
        return randomBytes(BLOCK_LENGTH);
    }
}
