package com.codeheadsystems.crypto.cipher;

import com.codeheadsystems.crypto.password.SecretKeyExpiredException;
import com.codeheadsystems.crypto.password.SecretKeyWrapper;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * BSD-Style License 2016
 */
public interface CipherProvider {

    public Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException;

    public SecretKeySpec getSecret(SecretKeyWrapper secretKeyWrapper) throws SecretKeyExpiredException;
}
