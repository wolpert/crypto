package com.codeheadsystems.crypto.cipher;

import com.codeheadsystems.crypto.CryptoException;
import com.codeheadsystems.crypto.Decrypter;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.codeheadsystems.crypto.Utilities.getCharset;
import static com.codeheadsystems.crypto.Utilities.reduce;

/**
 * BSD-Style License 2016
 */
public class ParanoidDecrypter implements Decrypter {

    private static final Logger logger = LoggerFactory.getLogger(ParanoidDecrypter.class);

    private final CipherProvider cipherProvider;

    public ParanoidDecrypter(CipherProvider cipherProvider) {
        this.cipherProvider = cipherProvider;
    }

    @Override
    public String decryptText(KeyParameterWrapper keyParameterWrapper, String encryptedText) throws CryptoException, SecretKeyExpiredException {
        return decryptText(keyParameterWrapper, encryptedText.getBytes(getCharset()));
    }

    @Override
    public String decryptText(KeyParameterWrapper keyParameterWrapper, byte[] encryptedBytes) throws CryptoException, SecretKeyExpiredException {
        return keyParameterWrapper.processWithKeyParameter((keyParameter -> decryptText(keyParameter, encryptedBytes)));
    }

    @Override
    public String decryptText(KeyParameter keyParameter, byte[] encryptedBytes) throws CryptoException {
        return new String(decryptBytes(keyParameter, encryptedBytes), getCharset());
    }

    @Override
    public byte[] decryptBytes(KeyParameterWrapper keyParameterWrapper, byte[] encryptedBytes) throws CryptoException, SecretKeyExpiredException {
        return keyParameterWrapper.processWithKeyParameter((keyParameter -> decryptBytes(keyParameter, encryptedBytes)));
    }

    @Override
    public String decryptText(KeyParameter keyParameter, String encryptedText) throws CryptoException {
        return decryptText(keyParameter, encryptedText.getBytes(getCharset()));
    }

    @Override
    public byte[] decryptBytes(KeyParameter keyParameter, byte[] encryptedBytes) throws CryptoException {
        logger.debug("decryptBytes()");
        try {
            return cipherProvider.callWithCipher((cipher) -> {
                EncryptedByteHolder encryptedByteHolder = EncryptedByteHolder.fromBytes(encryptedBytes);
                ParametersWithIV keyWithIv = new ParametersWithIV(keyParameter, encryptedByteHolder.getIv());
                cipher.init(false, keyWithIv);
                byte[] cipherBytes = encryptedByteHolder.getEncryptedBytes();
                byte[] decryptedBytes = new byte[cipher.getOutputSize(cipherBytes.length)];
                final int length1 = cipher.processBytes(cipherBytes, 0, cipherBytes.length, decryptedBytes, 0);
                final int length2 = cipher.doFinal(decryptedBytes, length1);
                return reduce(decryptedBytes, length1 + length2);
            });
        } catch (InvalidCipherTextException e) {
            throw new CryptoException("Unable to decrypt bytes due to " + e.getLocalizedMessage(), e);
        }
    }
}
