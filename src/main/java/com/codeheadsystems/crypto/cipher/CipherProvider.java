package com.codeheadsystems.crypto.cipher;

import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;

/**
 * BSD-Style License 2016
 */
public interface CipherProvider {

    PaddedBufferedBlockCipher getCipher();

    byte[] getRandomIV();
}
