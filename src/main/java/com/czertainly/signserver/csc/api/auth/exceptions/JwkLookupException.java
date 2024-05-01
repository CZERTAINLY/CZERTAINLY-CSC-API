package com.czertainly.signserver.csc.api.auth.exceptions;

import com.czertainly.signserver.csc.common.exceptions.ApplicationException;

public class JwkLookupException extends ApplicationException {

        public JwkLookupException(String message) {
            super(message);
        }

        public JwkLookupException(String message, Throwable cause) {
            super(message, cause);
        }
}
