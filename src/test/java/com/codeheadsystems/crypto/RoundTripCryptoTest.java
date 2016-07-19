package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.cipher.EncryptedByteHolder;
import com.codeheadsystems.crypto.decrypter.ParanoidDecrypter;
import com.codeheadsystems.crypto.encrypter.ParanoidEncrypter;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.PasswordHolder;
import com.codeheadsystems.crypto.password.KeyParameterBuilder;
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
        PasswordHolder passwordHolder = PasswordHolder.generate(password);
        byte[] salt = passwordHolder.getSalt();
        KeyParameterWrapper keyParameterWrapper = new KeyParameterBuilder().passwordHolder(passwordHolder).build();
        Encrypter encrypter = new ParanoidEncrypter(keyParameterWrapper);
        EncryptedByteHolder encryptBytes = encrypter.encryptBytes(clearText);
        assertNotEquals(clearText, new String(encryptBytes.getEncryptedBytes(), getCharset()));

        passwordHolder = PasswordHolder.generate(password, salt);
        keyParameterWrapper = new KeyParameterBuilder().passwordHolder(passwordHolder).build();
        Decrypter decrypter = new ParanoidDecrypter(keyParameterWrapper);
        String decryptedText = decrypter.decryptText(encryptBytes);
        assertEquals(clearText.length(), decryptedText.length());
        assertEquals(clearText, decryptedText);
    }

}
