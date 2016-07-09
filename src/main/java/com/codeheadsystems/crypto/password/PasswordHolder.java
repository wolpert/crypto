package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.Utilities;

/**
 * When reading a password from a user... use the generate one. If a file exists, the file needs
 * the salt. (Each file gets its own salt... tyvm.) If you do not have one, you can call generate
 * and make sure you store the salt afterwards.
 *
 * BSD-Style License 2016
 */
public class PasswordHolder {

    protected char[] password;
    protected byte[] salt;

    private PasswordHolder() {
    }

    public static PasswordHolder generate(String password) {
        return generate(password, Utilities.randomBytes(20));
    }

    public static PasswordHolder generate(String password, byte[] salt) {
        return generate(password.toCharArray(), salt);
    }

    public static PasswordHolder generate(char[] password) {
        return generate(password, Utilities.randomBytes(20));
    }

    public static PasswordHolder generate(char[] password, byte[] salt) {
        PasswordHolder passwordHolder = new PasswordHolder();
        passwordHolder.password = password;
        passwordHolder.salt = salt;
        return passwordHolder;
    }

    public char[] getPassword() {
        return password;
    }

    public byte[] getSalt() {
        return salt;
    }
}
