package com.czertainly.csc.signing.filter;

import com.czertainly.csc.signing.configuration.SignatureFormat;
import com.czertainly.csc.signing.configuration.WorkerCapabilities;
import com.czertainly.csc.utils.configuration.WorkerCapabilitiesBuilder;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SignatureFormatCriterionTest {

     @Test
     void matchesReturnsTrueOnMatchingSignatureFormat() {
         // given
         WorkerCapabilities workerCapabilities = WorkerCapabilitiesBuilder.create()
                                                                          .withSignatureFormat(SignatureFormat.XAdES)
                                                                          .build();
         SignatureFormatCriterion signatureFormatCriterion = new SignatureFormatCriterion(SignatureFormat.XAdES);

         // when
         boolean isMatch = signatureFormatCriterion.matches(workerCapabilities);

         // then
         assertTrue(isMatch);
     }

     @Test
     void matchesReturnsFalseOnNonMatchingSignatureFormat() {
         // given
         WorkerCapabilities workerCapabilities = WorkerCapabilitiesBuilder.create()
                                                                          .withSignatureFormat(SignatureFormat.XAdES)
                                                                          .build();
         SignatureFormatCriterion signatureFormatCriterion = new SignatureFormatCriterion(SignatureFormat.CAdES);

         // when
         boolean isMatch = signatureFormatCriterion.matches(workerCapabilities);

         // then
         assertFalse(isMatch);
     }

}