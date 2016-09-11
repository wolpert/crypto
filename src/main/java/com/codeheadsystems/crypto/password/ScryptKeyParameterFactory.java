package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.Hasher;
import com.codeheadsystems.crypto.hasher.HasherBuilder;
import com.codeheadsystems.crypto.hasher.ScryptHasherProviderImpl;
import com.codeheadsystems.crypto.timer.TimerProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * BSD-Style License 2016
 */
public class ScryptKeyParameterFactory extends KeyParameterFactory {

    private static final Logger logger = LoggerFactory.getLogger(ScryptKeyParameterFactory.class);

    protected ScryptKeyParameterFactory(long expirationInMills, Hasher hasher, TimerProvider timerProvider) {
        super(expirationInMills, hasher, timerProvider);
        logger.debug("ScryptKeyParameterFactory(" + expirationInMills + "," + hasher + ")");
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
                    .hasherProviderClass(ScryptHasherProviderImpl.class)
                    .iterations(iterationCount)
                    .saltSize(32) // 256 bit
                    .build();
            return new ScryptKeyParameterFactory(expirationInMills, hasher, timerProvider);
        }
    }

}
