package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.cipher.EncryptedByteHolder;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;

/**
 * BSD-Style License 2016
 */
public interface Decrypter {

    public String decryptText(EncryptedByteHolder encryptedBytes) throws CryptoException, SecretKeyExpiredException;

    public byte[] decryptBytes(EncryptedByteHolder encryptedBytes) throws CryptoException, SecretKeyExpiredException;

}
