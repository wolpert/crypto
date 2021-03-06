package com.codeheadsystems.crypto.cipher;

import com.codeheadsystems.crypto.CryptoException;
import com.codeheadsystems.crypto.Encrypter;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;
import com.codeheadsystems.shash.impl.RandomProvider;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.codeheadsystems.crypto.Utilities.getCharset;
import static com.codeheadsystems.crypto.Utilities.reduce;
import static com.codeheadsystems.crypto.cipher.CipherProvider.KEY_BYTE_SIZE;

/**
 * BSD-Style License 2016
 */
public class ParanoidEncrypter implements Encrypter {

    private final static Logger logger = LoggerFactory.getLogger(ParanoidEncrypter.class);

    private final CipherProvider cipherProvider;
    private final RandomProvider randomProvider;

    public ParanoidEncrypter(CipherProvider cipherProvider, RandomProvider randomProvider) {
        this.cipherProvider = cipherProvider;
        this.randomProvider = randomProvider;
    }

    @Override
    public byte[] encryptBytes(KeyParameterWrapper keyParameterWrapper, String text) throws CryptoException, SecretKeyExpiredException {
        return keyParameterWrapper.processWithKeyParameter((keyParameter -> encryptBytes(keyParameter, text.getBytes(getCharset()))));
    }

    @Override
    public byte[] encryptBytes(KeyParameter keyParameter, String text) throws CryptoException {
        return encryptBytes(keyParameter, text.getBytes(getCharset()));
    }

    @Override
    public byte[] encryptBytes(KeyParameterWrapper keyParameterWrapper, byte[] bytes) throws CryptoException, SecretKeyExpiredException {
        return keyParameterWrapper.processWithKeyParameter(keyParameter -> encryptBytes(keyParameter, bytes));
    }

    @Override
    public byte[] encryptBytes(KeyParameter keyParameter, byte[] bytes) throws CryptoException {
        logger.debug("encryptBytes()");
        try {
            return cipherProvider.callWithCipher((cipher) -> {
                byte[] iv = randomProvider.getRandomBytes(KEY_BYTE_SIZE);

                ParametersWithIV keyWithIv = new ParametersWithIV(keyParameter, iv);
                cipher.init(true, keyWithIv);
                byte[] encryptedBytes = new byte[cipher.getOutputSize(bytes.length)];
                final int length1 = cipher.processBytes(bytes, 0, bytes.length, encryptedBytes, 0);
                final int length2 = cipher.doFinal(encryptedBytes, length1);
                return new EncryptedByteHolder(reduce(encryptedBytes, length1 + length2), iv).toBytes();
            });
        } catch (InvalidCipherTextException e) {
            throw new CryptoException("Unable to encrypt bytes due to " + e.getLocalizedMessage(), e);
        }
    }
}
