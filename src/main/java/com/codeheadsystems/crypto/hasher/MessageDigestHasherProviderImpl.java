package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * BSD-Style License 2016
 */
public class MessageDigestHasherProviderImpl implements HasherProvider {

    public MessageDigestHasherProviderImpl() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public Hasher getHasher(HasherConfiguration hasherConfiguration) {
        return new MessageDigestHasher(hasherConfiguration);
    }
}