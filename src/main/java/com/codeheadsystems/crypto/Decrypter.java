package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;

import org.bouncycastle.crypto.params.KeyParameter;

/**
 * BSD-Style License 2016
 */
public interface Decrypter {

    String decryptText(KeyParameterWrapper keyParameterWrapper, byte[] encryptedBytes) throws CryptoException, SecretKeyExpiredException;

    byte[] decryptBytes(KeyParameterWrapper keyParameterWrapper, byte[] encryptedBytes) throws CryptoException, SecretKeyExpiredException;

    String decryptText(KeyParameter keyParameter, byte[] encryptedBytes) throws CryptoException;

    byte[] decryptBytes(KeyParameter keyParameter, byte[] encryptedBytes) throws CryptoException;

}
