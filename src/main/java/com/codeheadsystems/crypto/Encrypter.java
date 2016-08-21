package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.cipher.EncryptedByteHolder;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;

import org.bouncycastle.crypto.params.KeyParameter;

/**
 * BSD-Style License 2016
 */
public interface Encrypter {

    byte[] encryptBytes(KeyParameterWrapper keyParameterWrapper, String text) throws CryptoException, SecretKeyExpiredException;

    byte[] encryptBytes(KeyParameter keyParameter, String text) throws CryptoException;

    byte[] encryptBytes(KeyParameterWrapper keyParameterWrapper, byte[] bytes) throws CryptoException, SecretKeyExpiredException;

    byte[] encryptBytes(KeyParameter keyParameter, byte[] bytes) throws CryptoException;

}
