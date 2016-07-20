package com.codeheadsystems.crypto.cipher;

import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;

import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;

/**
 * BSD-Style License 2016
 */
public class ParanoidCipherProvider implements CipherProvider {

    private final static int BLOCK_LENGTH = 16;

    protected final KeyParameterWrapper keyParameterWrapper;

    public ParanoidCipherProvider(KeyParameterWrapper keyParameterWrapper) {
        this.keyParameterWrapper = keyParameterWrapper;
    }

    @Override
    public PaddedBufferedBlockCipher getCipher() {
        return new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
    }

    @Override
    public byte[] getRandomIV() {
        return Utilities.randomBytes(BLOCK_LENGTH);
    }
}
