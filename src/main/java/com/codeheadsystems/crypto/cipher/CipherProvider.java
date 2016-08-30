package com.codeheadsystems.crypto.cipher;

import org.bouncycastle.crypto.modes.AEADBlockCipher;

/**
 * BSD-Style License 2016
 */
public interface CipherProvider {

    AEADBlockCipher getCipher();

    byte[] getRandomIV();
}
