package com.codeheadsystems.crypto.cipher;

import com.codeheadsystems.crypto.password.SecretKeyExpiredException;
import com.codeheadsystems.crypto.password.SecretKeyWrapper;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * BSD-Style License 2016
 */
public class ParanoidCipherProvider implements CipherProvider {

    private final static String ALGORITHM = "AES/CBC/PKCS7Padding";

    public ParanoidCipherProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance(ALGORITHM);
    }

    @Override
    public SecretKeySpec getSecret(SecretKeyWrapper secretKeyWrapper) throws SecretKeyExpiredException {
        return new SecretKeySpec(secretKeyWrapper.getSecretKey().getEncoded(), "AES");
    }
}
