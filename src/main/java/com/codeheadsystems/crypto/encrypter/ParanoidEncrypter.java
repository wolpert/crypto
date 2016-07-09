package com.codeheadsystems.crypto.encrypter;

import com.codeheadsystems.crypto.CryptoException;
import com.codeheadsystems.crypto.Encrypter;
import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.cipher.EncryptedByteHolder;
import com.codeheadsystems.crypto.cipher.ParanoidCipherProvider;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;
import com.codeheadsystems.crypto.password.SecretKeyWrapper;

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import static com.codeheadsystems.crypto.Utilities.getCharset;

/**
 * BSD-Style License 2016
 */
public class ParanoidEncrypter extends ParanoidCipherProvider implements Encrypter {

    private final SecretKeyWrapper secretKeyWrapper;

    public ParanoidEncrypter(SecretKeyWrapper secretKeyWrapper) {
        this.secretKeyWrapper = secretKeyWrapper;
    }

    @Override
    public EncryptedByteHolder encryptBytes(String text) throws CryptoException, SecretKeyExpiredException {
        return encryptBytes(text.getBytes(getCharset()));
    }

    @Override
    public EncryptedByteHolder encryptBytes(byte[] bytes) throws CryptoException, SecretKeyExpiredException {
        try {
            Cipher cipher = getCipher();
            cipher.init(Cipher.ENCRYPT_MODE, getSecret(secretKeyWrapper));

            AlgorithmParameters params = cipher.getParameters();
            byte[] ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
            byte[] cryptedText = cipher.doFinal(bytes);
            return new EncryptedByteHolder(cryptedText, ivBytes);
        } catch (InvalidParameterSpecException | NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            throw new CryptoException("Unable to encrypt bytes due to " + e.getLocalizedMessage(), e);
        }
    }
}
