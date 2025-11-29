package com.czertainly.csc.signing.filter;

import com.czertainly.csc.signing.configuration.DocumentType;
import com.czertainly.csc.signing.configuration.WorkerCapabilities;

public class DocumentTypeCriterion implements Criterion<WorkerCapabilities> {

    private final DocumentType documentType;

    public DocumentTypeCriterion(DocumentType documentType) {
        this.documentType = documentType;
    }

    @Override
    public boolean matches(WorkerCapabilities element) {
        // check if the worker supports the specified document type
        return element.documentTypes().stream()
                      .anyMatch(type -> type.equals(documentType));
    }
}
