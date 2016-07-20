package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.cipher.EncryptedByteHolder;
import com.codeheadsystems.crypto.cipher.ParanoidDecrypter;
import com.codeheadsystems.crypto.cipher.ParanoidEncrypter;
import com.codeheadsystems.crypto.password.KeyParameterFactory;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;

import org.junit.Test;

import static com.codeheadsystems.crypto.Utilities.getCharset;
import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 * BSD-Style License 2016
 */
public class RoundTripCryptoTest {

    @Test
    public void testRoundTrip() throws SecretKeyExpiredException {
        String password = "lkfdsaf0oudsajhklfdsaf7ds0af7uaoshfkldsf9s67yfihsdka";
        String clearText = "This is not a test... wait... it is...";
        KeyParameterWrapper encryptKeyParameterWrapper = new KeyParameterFactory()
                .generate(password);
        Encrypter encrypter = new ParanoidEncrypter(encryptKeyParameterWrapper);
        EncryptedByteHolder encryptBytes = encrypter.encryptBytes(clearText);
        assertNotEquals(clearText, new String(encryptBytes.getEncryptedBytes(), getCharset()));
        byte[] salt = encryptKeyParameterWrapper.getSalt();

        // rebuild the keyParams
        KeyParameterWrapper decryptKeyParameterWrapper = new KeyParameterFactory().generate(password, salt);
        Decrypter decrypter = new ParanoidDecrypter(decryptKeyParameterWrapper);
        String decryptedText = decrypter.decryptText(encryptBytes);
        assertEquals(clearText.length(), decryptedText.length());
        assertEquals(clearText, decryptedText);
    }

}
