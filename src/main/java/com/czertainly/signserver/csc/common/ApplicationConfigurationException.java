package com.czertainly.signserver.csc.common;

public class ApplicationConfigurationException extends ApplicationException {

        public ApplicationConfigurationException(String message) {
            super(message);
        }

        public ApplicationConfigurationException(String message, Throwable cause) {
            super(message, cause);
        }
}
