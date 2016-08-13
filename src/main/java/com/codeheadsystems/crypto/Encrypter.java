package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.cipher.EncryptedByteHolder;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;

/**
 * BSD-Style License 2016
 */
public interface Encrypter {

    EncryptedByteHolder encryptBytes(KeyParameterWrapper keyParameterWrapper, String text) throws CryptoException, SecretKeyExpiredException;

    EncryptedByteHolder encryptBytes(KeyParameterWrapper keyParameterWrapper, byte[] bytes) throws CryptoException, SecretKeyExpiredException;

}
