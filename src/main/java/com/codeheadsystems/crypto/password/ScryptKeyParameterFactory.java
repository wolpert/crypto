package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.Hasher;
import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.hasher.HasherBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * BSD-Style License 2016
 */
public class ScryptKeyParameterFactory extends KeyParameterFactory {

    private static int SALT_SIZE = 32;
    private static final Logger logger = LoggerFactory.getLogger(ScryptKeyParameterFactory.class);

    protected ScryptKeyParameterFactory(long expirationInMills, Hasher hasher) {
        super(expirationInMills, hasher);
        logger.debug("ScryptKeyParameterFactory(" + expirationInMills + "," + hasher + ")");
    }

    @Override
    public byte[] getSalt() {
        return Utilities.randomBytes(32);
    }

    public static class Builder extends AbstractKeyParameterFactoryBuilder<ScryptKeyParameterFactory> {

        @Override
        public AbstractKeyParameterFactoryBuilder iterationCount(int iterationCount) {
            if (iterationCount < 16384) {
                throw new IllegalArgumentException("Unable to have an iteration count less then 16384: found " + iterationCount);
            }
            return super.iterationCount(iterationCount);
        }

        @Override
        public ScryptKeyParameterFactory build() {
            Hasher hasher = new HasherBuilder()
                    .iterations(iterationCount)
                    .saltSize(SALT_SIZE) // 256 bit
                    .build();
            return new ScryptKeyParameterFactory(expirationInMills, hasher);
        }
    }

}
