package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.Hasher;
import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.hasher.HasherBuilder;
import com.codeheadsystems.crypto.hasher.ParanoidHasherProviderImpl;

import org.bouncycastle.crypto.params.KeyParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Timer;

import static com.codeheadsystems.crypto.Utilities.stringToBytes;

/**
 * BSD-Style License 2016
 */
public class ParanoidKeyParameterFactory extends AbstractKeyParameterFactory {

    private static final Logger logger = LoggerFactory.getLogger(ParanoidKeyParameterFactory.class);

    protected ParanoidKeyParameterFactory(int expirationInMins, Hasher hasher) {
        super(expirationInMins, hasher);
        logger.debug("ParanoidKeyParameterFactory("+expirationInMins+","+hasher+")");
    }

    public static class Builder {
        int iterationCount = (int) Math.pow(2, 20); // minimum is 2^14. We do 2^20 for this sensitive data
        int expirationInMins = 10;

        public Builder iterationCount(int iterationCount) {
            if (iterationCount < 16384) {
                throw new IllegalArgumentException("Unable to have an iteration count less then 16384: found " + iterationCount);
            }
            this.iterationCount = iterationCount;
            return this;
        }

        public Builder expirationInMins(int expirationInMins) {
            this.expirationInMins = expirationInMins;
            return this;
        }

        public ParanoidKeyParameterFactory build() {
            Hasher hasher = new HasherBuilder()
                    .hasherProviderClass(ParanoidHasherProviderImpl.class)
                    .iterations(iterationCount)
                    .saltSize(16) // 128 bit
                    .build();
            return new ParanoidKeyParameterFactory(expirationInMins, hasher);
        }
    }

}
