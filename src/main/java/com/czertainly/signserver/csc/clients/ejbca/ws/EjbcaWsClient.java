package com.czertainly.signserver.csc.clients.ejbca.ws;

import com.czertainly.signserver.csc.clients.ejbca.ws.dto.*;
import com.czertainly.signserver.csc.clients.signserver.ws.SignserverWsClient;
import jakarta.xml.bind.JAXBElement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ws.client.core.support.WebServiceGatewaySupport;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Locale;

public class EjbcaWsClient extends WebServiceGatewaySupport {

    private static final Logger logger = LoggerFactory.getLogger(SignserverWsClient.class);

    public static final String WEB_SERVICE_BASE_PATH = "/ejbcaws/ejbcaws";

    private final String caName;
    private final String endEntityProfileName;
    private final String certificateProfileName;

    private final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssxxx",
                                                                                    Locale.getDefault()
    );

    public EjbcaWsClient(String ejbcaUrl, String caName, String endEntityProfileName, String certificateProfileName) {
        super();
        setDefaultUri(ejbcaUrl + WEB_SERVICE_BASE_PATH);
        this.caName = caName;
        this.endEntityProfileName = endEntityProfileName;
        this.certificateProfileName = certificateProfileName;
    }

    public EditUserResponse editUser(String username, String password, String subjectDn) {
        var request = new EditUser();
        var userDataVOWS = new UserDataVOWS();
        userDataVOWS.setUsername(username);
        userDataVOWS.setPassword(password);
        userDataVOWS.setSubjectDN(subjectDn);
        userDataVOWS.setCaName(caName);
        userDataVOWS.setEndEntityProfileName(endEntityProfileName);
        userDataVOWS.setCertificateProfileName(certificateProfileName);
        userDataVOWS.setStatus(10); // 10 = New
        userDataVOWS.setTokenType("USERGENERATED");
        request.setArg0(userDataVOWS);


        logger.info("Editing EJBCA user '" + username + " '.");
        var response = (JAXBElement<EditUserResponse>) getWebServiceTemplate().marshalSendAndReceive(request);
        return response.getValue();
    }

    public CertificateRequestResponse requestCertificate(String username, String password, String subjectDn, byte[] csr,
                                                         ZonedDateTime certificateValidityStart,
                                                         ZonedDateTime certificateValidityEnd
    ) {

        var csrBase64 = Base64.getEncoder().encodeToString(csr);
        System.out.println(dateTimeFormatter.format(certificateValidityStart));
        var request = new CertificateRequest();
        var userDataVOWS = new UserDataVOWS();
        userDataVOWS.setUsername(username);
        userDataVOWS.setPassword(password);
        userDataVOWS.setSubjectDN(subjectDn);
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

        logger.info("Requesting certificate for EJBCA user '" + username + " '.");
        var response = (JAXBElement<CertificateRequestResponse>) getWebServiceTemplate().marshalSendAndReceive(request);
        return response.getValue();
    }
}
