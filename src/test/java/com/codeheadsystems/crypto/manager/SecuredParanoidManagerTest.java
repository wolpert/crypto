package com.codeheadsystems.crypto.manager;

import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.random.UnsecureRandomProvider;

import org.junit.Before;
import org.junit.Test;

/**
 * BSD-Style License 2016
 */
public class SecuredParanoidManagerTest {

    @Before
    public void setRandomFactory() {
        Utilities.setRandomProvider(new UnsecureRandomProvider());
    }

    @Test(expected = ParanoidManagerException.class)
    public void testFailureInCreationWithUnsecureRandomProvider() throws ParanoidManagerException {
        new SecuredParanoidManager();
    }
}
