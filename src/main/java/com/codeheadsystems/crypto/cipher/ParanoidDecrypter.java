package com.codeheadsystems.crypto.cipher;

import com.codeheadsystems.crypto.CryptoException;
import com.codeheadsystems.crypto.Decrypter;
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
public class ParanoidDecrypter extends ParanoidCipherProvider implements Decrypter {

    private static final Logger logger = LoggerFactory.getLogger(ParanoidDecrypter.class);

    public ParanoidDecrypter(KeyParameterWrapper keyParameterWrapper) {
        super(keyParameterWrapper);
    }

    @Override
    public String decryptText(EncryptedByteHolder encryptedBytes) throws CryptoException, SecretKeyExpiredException {
        return new String(decryptBytes(encryptedBytes), getCharset());
    }

    @Override
    public byte[] decryptBytes(EncryptedByteHolder encryptedBytes) throws CryptoException, SecretKeyExpiredException {
        logger.debug("decryptBytes()");
        try {
            PaddedBufferedBlockCipher cipher = getCipher();
            ParametersWithIV keyWithIv = new ParametersWithIV(keyParameterWrapper.getKeyParameter(), encryptedBytes.getIv());
            cipher.init(false, keyWithIv);
            byte[] cipherBytes = encryptedBytes.getEncryptedBytes();
            byte[] decryptedBytes = new byte[cipher.getOutputSize(cipherBytes.length)];
            final int length1 = cipher.processBytes(cipherBytes, 0, cipherBytes.length, decryptedBytes, 0);
            final int length2 = cipher.doFinal(decryptedBytes, length1);
            return reduce(decryptedBytes, length1 + length2);
        } catch (InvalidCipherTextException e) {
            throw new CryptoException("Unable to decrypt bytes due to " + e.getLocalizedMessage(), e);
        }
    }
}
