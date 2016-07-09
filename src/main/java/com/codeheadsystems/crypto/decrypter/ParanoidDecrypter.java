package com.codeheadsystems.crypto.decrypter;

import com.codeheadsystems.crypto.CryptoException;
import com.codeheadsystems.crypto.Decrypter;
import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.cipher.EncryptedByteHolder;
import com.codeheadsystems.crypto.cipher.ParanoidCipherProvider;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;
import com.codeheadsystems.crypto.password.SecretKeyWrapper;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import static com.codeheadsystems.crypto.Utilities.*;

/**
 * BSD-Style License 2016
 */
public class ParanoidDecrypter extends ParanoidCipherProvider implements Decrypter {

    private final SecretKeyWrapper secretKeyWrapper;

    public ParanoidDecrypter(SecretKeyWrapper secretKeyWrapper) {
        this.secretKeyWrapper = secretKeyWrapper;
    }

    @Override
    public String decryptText(EncryptedByteHolder encryptedBytes) throws CryptoException, SecretKeyExpiredException {
        return new String(decryptBytes(encryptedBytes), getCharset());
    }

    @Override
    public byte[] decryptBytes(EncryptedByteHolder encryptedBytes) throws CryptoException, SecretKeyExpiredException {
        try {
            Cipher cipher = getCipher();
            cipher.init(Cipher.DECRYPT_MODE, getSecret(secretKeyWrapper), new IvParameterSpec(encryptedBytes.getIv()));
            return cipher.doFinal(encryptedBytes.getEncryptedBytes());
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            throw new CryptoException("Unable to decrypt bytes due to " + e.getLocalizedMessage(), e);
        }
    }
}
