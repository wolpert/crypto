package com.codeheadsystems.crypto.cipher;

import com.codeheadsystems.crypto.CryptoException;
import com.codeheadsystems.crypto.Encrypter;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.codeheadsystems.crypto.Utilities.getCharset;
import static com.codeheadsystems.crypto.Utilities.reduce;

/**
 * BSD-Style License 2016
 */
public class ParanoidEncrypter extends ParanoidCipherProvider implements Encrypter {

    private final static Logger logger = LoggerFactory.getLogger(ParanoidEncrypter.class);

    public ParanoidEncrypter(KeyParameterWrapper keyParameterWrapper) {
        super(keyParameterWrapper);
    }

    @Override
    public EncryptedByteHolder encryptBytes(String text) throws CryptoException, SecretKeyExpiredException {
        return encryptBytes(text.getBytes(getCharset()));
    }

    @Override
    public EncryptedByteHolder encryptBytes(byte[] bytes) throws CryptoException, SecretKeyExpiredException {
        logger.debug("encryptBytes()");
        try {
            PaddedBufferedBlockCipher cipher = getCipher();
            byte[] iv = getRandomIV();

            ParametersWithIV keyWithIv = new ParametersWithIV(keyParameterWrapper.getKeyParameter(), iv);
            cipher.init(true, keyWithIv);
            byte[] encryptedBytes = new byte[cipher.getOutputSize(bytes.length)];
            final int length1 = cipher.processBytes(bytes, 0, bytes.length, encryptedBytes, 0);
            final int length2 = cipher.doFinal(encryptedBytes, length1);
            return new EncryptedByteHolder(reduce(encryptedBytes, length1 + length2), iv);
        } catch (InvalidCipherTextException e) {
            throw new CryptoException("Unable to encrypt bytes due to " + e.getLocalizedMessage(), e);
        }
    }
}
