package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.cipher.EncryptedByteHolder;
import com.codeheadsystems.crypto.decrypter.ParanoidDecrypter;
import com.codeheadsystems.crypto.encrypter.ParanoidEncrypter;
import com.codeheadsystems.crypto.password.PasswordHolder;
import com.codeheadsystems.crypto.password.SecretKeyBuilder;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;
import com.codeheadsystems.crypto.password.SecretKeyWrapper;

import org.junit.Test;

import static junit.framework.TestCase.assertEquals;

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
        SecretKeyWrapper secretKeyWrapper = new SecretKeyBuilder().passwordHolder(passwordHolder).build();
        Encrypter encrypter = new ParanoidEncrypter(secretKeyWrapper);
        EncryptedByteHolder encryptBytes = encrypter.encryptBytes(clearText);

        passwordHolder = PasswordHolder.generate(password, salt);
        secretKeyWrapper = new SecretKeyBuilder().passwordHolder(passwordHolder).build();
        Decrypter decrypter = new ParanoidDecrypter(secretKeyWrapper);
        assertEquals(clearText, decrypter.decryptText(encryptBytes));
    }

}
