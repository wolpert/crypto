package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.Hasher;
import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.hasher.HasherBuilder;
import com.codeheadsystems.crypto.hasher.ParanoidHasherProviderImpl;

import org.bouncycastle.jcajce.provider.digest.Skein;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * When reading a password from a user... use the generate one. If a file exists, the file needs
 * the salt. (Each file gets its own salt... tyvm.) If you do not have one, you can call generate
 * and make sure you store the salt afterwards.
 * <p/>
 * BSD-Style License 2016
 */
public class PasswordHolder {

    protected byte[] password;
    protected byte[] salt;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static PasswordHolder generate(String password) {
        return generate(password, Utilities.randomBytes(20));
    }

    public static PasswordHolder generate(String password, byte[] salt) {
        PasswordHolder passwordHolder = new PasswordHolder();
        Hasher hasher = new HasherBuilder()
                .hasherProviderClass(ParanoidHasherProviderImpl.class)
                .digest("SKEIN-512-256")
                .build();
        passwordHolder.password = hasher.generateHash(password, salt).getHash();
        passwordHolder.salt = salt;
        return passwordHolder;
    }

    public byte[] getPassword() {
        return password;
    }

    public byte[] getSalt() {
        return salt;
    }
}
