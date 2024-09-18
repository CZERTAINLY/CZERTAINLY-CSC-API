package com.czertainly.csc.clients.ejbca;

import com.czertainly.csc.clients.ejbca.ws.EjbcaWsClient;
import com.czertainly.csc.clients.ejbca.ws.dto.CertificateResponse;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.model.RevocationStatus;
import com.czertainly.csc.model.ejbca.EndEntity;
import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Period;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Objects;

@Component
public class EjbcaClient {

    private static final Logger logger = LoggerFactory.getLogger(EjbcaClient.class);

    private final EjbcaWsClient ejbcaWsClient;
    private final Period certificateValidity;

    public EjbcaClient(EjbcaWsClient ejbcaWsClient) {
        this.ejbcaWsClient = ejbcaWsClient;
        this.certificateValidity = Period.ofDays(365);
    }

    public Result<EndEntity, TextError> createEndEntity(EndEntity endEntity) {
        logger.debug("Creating new end entity for user '{}'", endEntity.username());
        logger.trace(endEntity.toString());
        return ejbcaWsClient.editUser(endEntity.username(), endEntity.password(), endEntity.subjectDN(),
                                      endEntity.san()
                            )
                            .map((v) -> endEntity)
                            .mapError(e -> e.extend("Failed to create end entity %s.", endEntity.username()))
                            .ifSuccess(() -> logger.info("New End Entity {} was created.", endEntity.username()))
                            .consumeError((e) -> logger.info(e.toString()));
    }

    /*
     * Returns a byte array containing the signed certificate with complete chain in PKCS7 format.
     */
    public Result<byte[], TextError> signCertificateRequest(EndEntity endEntity, byte[] csr) {
        ZonedDateTime validityStart = ZonedDateTime.now();
        ZonedDateTime validityEnd = validityStart.plus(certificateValidity);
        return ejbcaWsClient.requestCertificate(endEntity.username(), endEntity.password(), endEntity.subjectDN(), csr,
                                                validityStart, validityEnd
                            ).map(CertificateResponse::getData)
                            .map(base64Bytes -> ArrayUtils.removeAllOccurrences(base64Bytes, (byte) '\n'))
                            .flatMap(base64BytesWithoutNewLines -> {
                                try {
                                    byte[] decoded = Base64.getDecoder().decode(base64BytesWithoutNewLines);
                                    return Result.success(decoded);
                                } catch (Exception e) {
                                    logger.error("Can't decode signed certificate provided by End Entity {}",
                                                 endEntity.username(), e
                                    );
                                    return Result.error(
                                            TextError.of("Failed to decode certificate returned by end entity %s. %s",
                                                         endEntity.username(), e.getMessage()
                                            )
                                    );
                                }
                            });
    }

    public Result<RevocationStatus, TextError> getCertificateRevocationStatus(
            String certificateSerialNumberHex, String issuerDN
    ) {
        return ejbcaWsClient
                .checkRevocationStatus(issuerDN, certificateSerialNumberHex)
                .validate(
                        status -> (status.getIssuerDN() == null || status.getCertificateSN() == null),
                        TextError.of("Certificate %s issued by %s not found in EJBCA",
                                     certificateSerialNumberHex,
                                     issuerDN
                        )
                )
                .validate(
                        status -> !Objects.equals(status.getIssuerDN(), issuerDN),
                        status -> TextError.of(
                                "Revocation status for different certificate received. Issuer of requested certificate is %s, but received for certificate issued by %s",
                                certificateSerialNumberHex, status.getCertificateSN()
                        )
                )
                .validate(
                        status -> !Objects.equals(status.getCertificateSN(), certificateSerialNumberHex),
                        status -> TextError.of(
                                "Revocation status for different certificate received. Requested for SN %s, received for SN %s",
                                certificateSerialNumberHex, status.getCertificateSN()
                        )
                ).map(status -> {
                    if (status.getReason() == 6) {
                        return RevocationStatus.SUSPENDED;
                    }
                    return status.getReason() == -1 ? RevocationStatus.NOT_REVOKED : RevocationStatus.REVOKED;
                })
                .mapError(e -> e.extend("Failed to get revocation status for certificate %s issued by %s",
                                        certificateSerialNumberHex, issuerDN
                ));
    }

    public Result<?, TextError> revokeCertificate(String certificateSerialNumberHex, String issuerDN) {
        return ejbcaWsClient.revokeCertificate(issuerDN, certificateSerialNumberHex)
                            .mapError(e -> e.extend("Failed to revoke certificate '%s' issued by '%s'",
                                                   certificateSerialNumberHex, issuerDN
                            ));
    }

    public Result<EndEntity, TextError> getEndEntity(String username) {
        return ejbcaWsClient.getUserData(username)
                            .map(data -> new EndEntity(data.getUsername(), data.getPassword(), data.getSubjectDN(),
                                                       data.getSubjectAltName()
                            ))
                            .mapError(e -> e.extend("Failed to get end entity %s", username));
    }
}