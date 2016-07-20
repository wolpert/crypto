package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.hasher.HasherBuilder;
import com.codeheadsystems.crypto.hasher.ParanoidHasherProviderImpl;

import org.bouncycastle.crypto.params.KeyParameter;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static com.codeheadsystems.crypto.Utilities.stringToBytes;

/**
 * BSD-Style License 2016
 */
public class KeyParameterFactory {

    private final int iterationCount;

    public KeyParameterFactory() {
        iterationCount = 65536;
    }

    public KeyParameterFactory(int iterationCount) {
        this.iterationCount = iterationCount;
    }

    public KeyParameterWrapper generate(String password) {
        return generate(password, Utilities.randomBytes(20));
    }

    public KeyParameterWrapper generate(String password, String salt) {
        return generate(password, stringToBytes(salt));
    }

    /**
     * Only can be used once. The password will have to be reset
     *
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public KeyParameterWrapper generate(String password, byte[] salt) {
        byte[] hashedPassword = new HasherBuilder()
                .hasherProviderClass(ParanoidHasherProviderImpl.class)
                .digest("SKEIN-512-256")
                .iterations(iterationCount)
                .saltSize(salt.length) // really just for logging
                .build()
                .generateHash(password, salt)
                .getHash();
        KeyParameter keyParameter = new KeyParameter(hashedPassword);
        KeyParameterWrapper secretKeyWrapper = new KeyParameterWrapper(keyParameter, salt);
        return secretKeyWrapper;
    }

}
