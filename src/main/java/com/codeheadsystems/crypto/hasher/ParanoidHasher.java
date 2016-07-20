package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * BSD-Style License 2016
 */
public class ParanoidHasher extends AbstractSaltedHasher<MessageDigest> implements Hasher {

    public ParanoidHasher(HasherConfiguration hasherConfiguration) {
        super(hasherConfiguration);
    }

    public MessageDigest getMessageDigest() {
        MessageDigest result = digesterThreadLocal.get();
        if (result == null) {
            try {
                result = MessageDigest.getInstance(digest);
            } catch (NoSuchAlgorithmException e) {
                throw new HasherException("Failure with Algorithm: " + digest, e);
            }
            digesterThreadLocal.set(result);
        }
        return result;
    }

    @Override
    protected byte[] internalGenerateHash(String unhashedString, byte[] salt) {
        byte[] hashingBytes = getBytes(unhashedString);
        MessageDigest messageDigest = getMessageDigest();
        try {
            messageDigest.update(salt);
            for (int i = 0; i < iterations; i++) {
                hashingBytes = messageDigest.digest(hashingBytes);
            }
        } finally {
            messageDigest.reset();
        }
        return hashingBytes;
    }

}
