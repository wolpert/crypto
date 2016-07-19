package com.codeheadsystems.crypto.cipher;

import com.codeheadsystems.crypto.password.SecretKeyExpiredException;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;

import javax.crypto.spec.SecretKeySpec;

/**
 * BSD-Style License 2016
 */
public interface CipherProvider {

    PaddedBufferedBlockCipher getCipher();

    byte[] getRandomIV();
}
