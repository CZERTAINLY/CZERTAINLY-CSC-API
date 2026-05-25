package com.otilm.csc.signing.configuration.process.token;

import java.util.List;

public interface SigningToken {

    String getKeyAlias();

    Boolean canSignData(List<String> data, int numberOfDocumentsAuthorizedBySad);

}
