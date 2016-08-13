package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.cipher.EncryptedByteHolder;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;

/**
 * BSD-Style License 2016
 */
public interface Decrypter {

    String decryptText(KeyParameterWrapper keyParameterWrapper, EncryptedByteHolder encryptedBytes) throws CryptoException, SecretKeyExpiredException;

    byte[] decryptBytes(KeyParameterWrapper keyParameterWrapper, EncryptedByteHolder encryptedBytes) throws CryptoException, SecretKeyExpiredException;

}
