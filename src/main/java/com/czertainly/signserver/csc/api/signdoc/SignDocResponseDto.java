package com.czertainly.signserver.csc.api.signdoc;

import com.czertainly.signserver.csc.api.BaseSignatureResponseDto;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

public class SignDocResponseDto extends BaseSignatureResponseDto {

        @Schema(
                description = """
                        One or more Base64-encoded signatures enveloped within the
                        documents. Returned only when requested the creation of signature(s) enveloped within the signed
                        document(s) and when operationMode is not `A`.
                        """
        )
        private final List<String> documentWithSignature;

        @Schema(
                description = """
                        One or more Base64-encoded signatures detached from the documents.
                        This element carries a value only if the client application requested
                        the creation of detached signature(s) and when operationMode is not `A`.
                        """
        )
        private final List<String> signatureObject;

        @Schema(
                description = """
                        The `validationInfo` data to be included in the signing response if requested using the input
                        parameter `returnValidationInfo`.
                        """
        )
        private final ValidationInfo validationInfo;

        public SignDocResponseDto(List<String> documentWithSignature, List<String> signatureObject,
                                  String responseId, ValidationInfo validationInfo) {
                super(responseId);
                this.documentWithSignature = documentWithSignature;
                this.signatureObject = signatureObject;
                this.validationInfo = validationInfo;
        }

        public List<String> getDocumentWithSignature() {
                return documentWithSignature;
        }

        public List<String> getSignatureObject() {
                return signatureObject;
        }

        public ValidationInfo getValidationInfo() {
                return validationInfo;
        }

}
