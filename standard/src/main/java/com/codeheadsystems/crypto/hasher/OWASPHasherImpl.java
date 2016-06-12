package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Java7 compatible hasher
 * <p/>
 * BSD-Style License 2016
 */
public class OWASPHasherImpl extends AbstractSaltedHasher<SecretKeyFactory> implements Hasher {

    protected int keySize;

    public OWASPHasherImpl(final HasherConfiguration hasherConfiguration) {
        super(hasherConfiguration);
        this.keySize = hasherConfiguration.keySize;
    }

    public SecretKeyFactory getSecretKeyFactory() {
        SecretKeyFactory result = digesterThreadLocal.get();
        if (result == null) {
            try {
                result = SecretKeyFactory.getInstance(digest);
            } catch (NoSuchAlgorithmException e) {
                throw new HasherException("Failure with Algorithm: " + digest, e);
            }
            digesterThreadLocal.set(result);
        }
        return result;
    }

    protected byte[] internalGenerateHash(String unhashedString, byte[] salt) {
        try {
            SecretKeyFactory skf = getSecretKeyFactory();
            PBEKeySpec spec = new PBEKeySpec(unhashedString.toCharArray(), salt, iterations, keySize);
            SecretKey key = skf.generateSecret(spec);
            return key.getEncoded();
        } catch (InvalidKeySpecException e) {
            throw new HasherException("Invalid KeySpec", e);
        }
    }
}
