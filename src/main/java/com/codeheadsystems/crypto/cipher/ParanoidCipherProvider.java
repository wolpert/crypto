package com.codeheadsystems.crypto.cipher;

import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;

import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * BSD-Style License 2016
 */
public class ParanoidCipherProvider implements CipherProvider {

    private final static Logger logger = LoggerFactory.getLogger(ParanoidCipherProvider.class);
    private final static int BLOCK_LENGTH = 16;

    protected final KeyParameterWrapper keyParameterWrapper;

    public ParanoidCipherProvider(KeyParameterWrapper keyParameterWrapper) {
        logger.debug("ParanoidCipherProvider()");
        this.keyParameterWrapper = keyParameterWrapper;
    }

    @Override
    public PaddedBufferedBlockCipher getCipher() {
        logger.debug("getCipher()");
        return new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
    }

    @Override
    public byte[] getRandomIV() {
        return Utilities.randomBytes(BLOCK_LENGTH);
    }
}
