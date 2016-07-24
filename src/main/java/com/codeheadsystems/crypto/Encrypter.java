package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.cipher.EncryptedByteHolder;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;

/**
 * BSD-Style License 2016
 */
public interface Encrypter {

    public EncryptedByteHolder encryptBytes(String text) throws CryptoException, SecretKeyExpiredException;

    public EncryptedByteHolder encryptBytes(byte[] bytes) throws CryptoException, SecretKeyExpiredException;

}
