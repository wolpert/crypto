package com.codeheadsystems.crypto.manager;

import com.codeheadsystems.crypto.Utilities;

/**
 * This version only differs from the ParanoidManager by enforcing the SecureRandomProvider.
 * BSD-Style License 2016
 */
public class SecuredParanoidManager extends ParanoidManager {
    public SecuredParanoidManager() throws ParanoidManagerException {
        super();
        if (!Utilities.isSecureRandomProvider()) {
            throw new ParanoidManagerException("Paranoid Manager will not operate without SecureRandom provider");
        }
    }
}
