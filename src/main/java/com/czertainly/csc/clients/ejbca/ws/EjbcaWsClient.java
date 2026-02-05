package com.czertainly.csc.clients.ejbca.ws;

import com.czertainly.csc.clients.ejbca.ws.dto.*;
import com.czertainly.csc.common.errorhandling.ErrorResultRetryException;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.common.result.TextErrorWithRetryIndication;
import com.czertainly.csc.model.CertificateRevocationReason;
import jakarta.xml.bind.JAXBElement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.ws.client.WebServiceIOException;
import org.springframework.ws.client.core.support.WebServiceGatewaySupport;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

@Retryable(retryFor = {ErrorResultRetryException.class}, maxAttempts = 3, backoff = @Backoff(delay = 1000, multiplier = 2), listeners = {"resultRetryListener"})
public class EjbcaWsClient extends WebServiceGatewaySupport {

    private static final Logger logger = LoggerFactory.getLogger(EjbcaWsClient.class);

    public static final String WEB_SERVICE_BASE_PATH = "/ejbcaws/ejbcaws";

    private final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(
            "yyyy-MM-dd HH:mm:ssxxx", Locale.getDefault());

    public EjbcaWsClient(String ejbcaUrl) {
        super();
        setDefaultUri(ejbcaUrl + WEB_SERVICE_BASE_PATH);
    }

    public Result<Void, TextError> editUser(String username, String password, String subjectDn, String san,
                                            String caName, String certificateProfileName, String endEntityProfileName
    ) {
        try {
            logger.info("Editing EJBCA user '{} '.", username);
            logger.trace("Subject DN: {}, SAN {}", subjectDn, san);
            var request = new EditUser();
            var userDataVOWS = new UserDataVOWS();
            userDataVOWS.setUsername(username);
            userDataVOWS.setPassword(password);
            userDataVOWS.setSubjectDN(subjectDn);
            userDataVOWS.setSubjectAltName(san);
            userDataVOWS.setCaName(caName);
            userDataVOWS.setEndEntityProfileName(endEntityProfileName);
            userDataVOWS.setCertificateProfileName(certificateProfileName);
            userDataVOWS.setStatus(10); // 10 = New
            userDataVOWS.setTokenType("USERGENERATED");
            request.setArg0(userDataVOWS);

            getWebServiceTemplate().marshalSendAndReceive(request);
            return Result.emptySuccess();
        } catch (WebServiceIOException e) {
            logger.error("Failed to edit EJBCA user '{}'.", username, e);
            return Result.error(TextErrorWithRetryIndication.doRetry("Failed to edit EJBCA user"));
        } catch (Exception e) {
            logger.error("Failed to edit EJBCA user '{}'.", username, e);
            return Result.error(TextErrorWithRetryIndication.doNotRetry("Failed to edit EJBCA user"));
        }
    }

    public Result<CertificateResponse, TextError> requestCertificate(
            String username, String password, String subjectDn, String subjectAlternativeName, byte[] csr,
            ZonedDateTime certificateValidityStart, ZonedDateTime certificateValidityEnd,
            String caName, String certificateProfileName, String endEntityProfileName
    ) {
        try {
            logger.debug("Requesting certificate for EJBCA user '{}", username);
            var csrBase64 = Base64.getEncoder().encodeToString(csr);
            var request = new CertificateRequest();
            var userDataVOWS = new UserDataVOWS();
            userDataVOWS.setUsername(username);
            userDataVOWS.setPassword(password);
            userDataVOWS.setSubjectDN(subjectDn);
            userDataVOWS.setSubjectAltName(subjectAlternativeName);
            userDataVOWS.setStartTime(dateTimeFormatter.format(certificateValidityStart));
            userDataVOWS.setEndTime(dateTimeFormatter.format(certificateValidityEnd));
            userDataVOWS.setCaName(caName);
            userDataVOWS.setEndEntityProfileName(endEntityProfileName);
            userDataVOWS.setCertificateProfileName(certificateProfileName);

            request.setArg0(userDataVOWS);
            request.setArg1(csrBase64); // requestData
            request.setArg2(0); // requestType; PKCS10 certificate request
            request.setArg3(null); // hardTokenSN; support dropped in EJBCA 7.1.0
            request.setArg4("PKCS7WITHCHAIN"); // responseType

            var response = (JAXBElement<CertificateRequestResponse>) getWebServiceTemplate().marshalSendAndReceive(
                    request);
            CertificateResponse cr = response.getValue().getReturn();
            return Result.success(cr);
        } catch (WebServiceIOException e) {
            logger.error("Certificate request has failed. Username={}, subjectDN={}.", username, subjectDn, e);
            return Result.error(TextErrorWithRetryIndication.doRetry("Certificate request has failed."));
        } catch (Exception e) {
            logger.error("Certificate request has failed. Username={}, subjectDN={}.", username, subjectDn, e);
            return Result.error(TextErrorWithRetryIndication.doNotRetry("Certificate request has failed."));
        }
    }

    public Result<RevokeStatus, TextError> checkRevocationStatus(String issuerDn, String serialNumberHex) {
        try {
            logger.debug("Checking revocation status for certificate with serial number {} issued by {}",
                         serialNumberHex, issuerDn
            );

            var request = new CheckRevokationStatus();
            request.setArg0(issuerDn);
            request.setArg1(serialNumberHex);

            var response = (JAXBElement<CheckRevokationStatusResponse>) getWebServiceTemplate().marshalSendAndReceive(
                    request);
            RevokeStatus status = response.getValue().getReturn();
            return Result.success(status);
        } catch (WebServiceIOException e) {
            logger.error("Failed to check revocation status for certificate with serial number {} issued by {}.",
                         serialNumberHex, issuerDn, e
            );
            return Result.error(TextErrorWithRetryIndication.doRetry("Failed to check revocation status."));
        } catch (Exception e) {
            logger.error("Failed to check revocation status for certificate with serial number {} issued by {}.",
                         serialNumberHex, issuerDn, e
            );
            return Result.error(TextErrorWithRetryIndication.doNotRetry("Failed to check revocation status."));
        }
    }

    public Result<Void, TextError> revokeCertificate(String certificateSerialNumberHex, String issuerDN,
                                                     CertificateRevocationReason revocationReason
    ) {
        try {
            logger.info("Revoking certificate with serial number '{}' issued by '{}' because of a reason '{}'.",
                        certificateSerialNumberHex, issuerDN, revocationReason
            );

            var request = new RevokeCert();
            request.setArg0(issuerDN); // certificateSerialNumberHex
            request.setArg1(certificateSerialNumberHex); // issuerDN
            request.setArg2(revocationReason.getReasonCode()); // reason

            getWebServiceTemplate().marshalSendAndReceive(request);
            return Result.emptySuccess();
        } catch (WebServiceIOException e) {
            logger.error("Failed to revoke certificate with serial number '{}' issued by '{}'.",
                         certificateSerialNumberHex, issuerDN, e
            );
            return Result.error(TextErrorWithRetryIndication.doRetry("Failed to revoke certificate."));
        } catch (Exception e) {
            logger.error("Failed to revoke certificate with serial number '{}' issued by '{}'.",
                         certificateSerialNumberHex, issuerDN, e
            );
            return Result.error(TextErrorWithRetryIndication.doNotRetry("Failed to revoke certificate."));
        }
    }

    public Result<UserDataVOWS, TextError> getUserData(String username) {
        try {
            logger.debug("Fetching user data for EJBCA user '{}'.", username);

            var request = new FindUser();
            var userMatch = new UserMatch();
            userMatch.setMatchwith(0); // 0 = username
            userMatch.setMatchtype(0); // 0 = exact match
            userMatch.setMatchvalue(username);
            request.setArg0(userMatch);

            var response = (JAXBElement<FindUserResponse>) getWebServiceTemplate().marshalSendAndReceive(request);
            List<UserDataVOWS> data = response.getValue().getReturn();
            if (data.isEmpty()) {
                return Result.error(TextError.of("User %s not found in EJBCA", username));
            } else if (data.size() > 1) {
                return Result.error(
                        TextError.of("Multiple instances of user data found for user %s. Can't choose one.", username));
            } else {
                return Result.success(data.getFirst());
            }
        } catch (WebServiceIOException e) {
            logger.error("Failed to fetch user data for EJBCA user {}", username, e);
            return Result.error(TextErrorWithRetryIndication.doRetry("Failed to fetch user data."));
        } catch (Exception e) {
            logger.error("Failed to fetch user data for EJBCA user {}", username, e);
            return Result.error(TextErrorWithRetryIndication.doNotRetry("Failed to fetch user data."));
        }
    }
}
