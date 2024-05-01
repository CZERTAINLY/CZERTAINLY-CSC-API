package com.czertainly.signserver.csc.clients.signserver.ws;

import com.czertainly.signserver.csc.clients.signserver.ws.dto.*;
import jakarta.xml.bind.JAXBElement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ws.client.core.support.WebServiceGatewaySupport;

public class SignserverWsClient extends WebServiceGatewaySupport {

    private static final Logger logger = LoggerFactory.getLogger(SignserverWsClient.class);

    public static final String WEB_SERVICE_BASE_PATH = "/AdminWSService/AdminWS";

    public SignserverWsClient(String signserverUrl) {
        super();
        setDefaultUri(signserverUrl + WEB_SERVICE_BASE_PATH);
    }

    public GetPKCS10CertificateRequestForAlias2Response generateCsr(
            int workerId, String keyAlias, String signatureAlgorithm, String dn
    ) {

        var request = new GetPKCS10CertificateRequestForAlias2();
        var certReqInfo = new Pkcs10CertReqInfo();

        certReqInfo.setSignatureAlgorithm(signatureAlgorithm);
        certReqInfo.setSubjectDN(dn);

        request.setSignerId(workerId);
        request.setKeyAlias(keyAlias);
        request.setCertReqInfo(certReqInfo);

        logger.info("Requesting CSR for key: " + keyAlias);
        var response = (JAXBElement<GetPKCS10CertificateRequestForAlias2Response>) getWebServiceTemplate()
                .marshalSendAndReceive(request);

        return response.getValue();
    }

    public QueryTokenEntriesResponse queryTokenEntries(int workerId, boolean includeData, int startIndex,
                                                       int numOfItems
    ) {
        var request = new QueryTokenEntries();
        request.setWorkerId(workerId);
        request.setIncludeData(includeData);
        request.setStartIndex(startIndex);
        request.setMax(startIndex + numOfItems);
        request.addCondition(new QueryCondition("alias", RelationalOperator.LIKE, "pregenerated___%"));


        logger.info("Querying token entries for worker: " + workerId);
        var response = (JAXBElement<QueryTokenEntriesResponse>) getWebServiceTemplate().marshalSendAndReceive(request);
        return response.getValue();
    }

    public ImportCertificateChainResponse importCertificateChain(int workerId, String keyAlias, byte[] chain) {
        var request = new ImportCertificateChain();
        request.setWorkerId(workerId);
        request.setAlias(keyAlias);
        request.setCertificateChain(new String(chain));

        logger.info("Importing certificate chain for key: " + keyAlias);
        var response = (JAXBElement<ImportCertificateChainResponse>) getWebServiceTemplate().marshalSendAndReceive(
                request);
        return response.getValue();
    }


}
