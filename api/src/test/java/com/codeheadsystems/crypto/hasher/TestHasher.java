package com.codeheadsystems.crypto.hasher;

/**
 * BSD-Style License 2016
 */
public class TestHasher extends AbstractSaltedHasher {

    public TestHasher(HasherConfiguration hasherConfiguration) {
        super(hasherConfiguration);
    }

    @Override
    protected byte[] internalGenerateHash(String unhashedString, byte[] salt) {
        return new byte[0];
    }
}
