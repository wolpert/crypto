package com.codeheadsystems.crypto.manager;

import com.codeheadsystems.crypto.Utilities;

/**
 * This version only differs from the ParanoidManager only by enforcing the SecureRandomProvider.
 * BSD-Style License 2016
 */
public class SecuredParanoidManager extends ParanoidManager {

    public SecuredParanoidManager() throws ParanoidManagerException {
        this(20);
    }

    public SecuredParanoidManager(int iterationExponential) throws ParanoidManagerException {
        super(iterationExponential);
        if (!Utilities.isSecureRandomProvider()) {
            throw new ParanoidManagerException("Paranoid Manager will not operate without SecureRandom provider");
        }
    }
}
