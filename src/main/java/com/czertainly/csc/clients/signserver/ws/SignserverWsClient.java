package com.czertainly.csc.clients.signserver.ws;

import com.czertainly.csc.clients.signserver.ws.dto.*;
import com.czertainly.csc.common.exceptions.RemoteSystemException;
import jakarta.xml.bind.JAXBElement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ws.client.core.support.WebServiceGatewaySupport;

import java.util.Base64;
import java.util.List;

public class SignserverWsClient extends WebServiceGatewaySupport {

    private static final Logger logger = LoggerFactory.getLogger(SignserverWsClient.class);

    public static final String WEB_SERVICE_BASE_PATH = "/AdminWSService/AdminWS";


    public SignserverWsClient(String signserverUrl) {
        super();
        setDefaultUri(signserverUrl + WEB_SERVICE_BASE_PATH);
    }

    public CertReqData generateCsr(
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
        try {
            var response = (JAXBElement<GetPKCS10CertificateRequestForAlias2Response>) getWebServiceTemplate()
                    .marshalSendAndReceive(request);
            return response.getValue().getReturn();
        } catch (Exception e) {
            throw new RemoteSystemException("CSR generation failed for worker " + workerId, e);
        }
    }

    public TokenSearchResults queryTokenEntries(int workerId, boolean includeData, int startIndex,
                                                int numOfItems, String keyAliasFilterPattern
    ) {
        var request = new QueryTokenEntries();
        request.setWorkerId(workerId);
        request.setIncludeData(includeData);
        request.setStartIndex(startIndex);
        request.setMax(startIndex + numOfItems);
        if (keyAliasFilterPattern != null) {
            request.addCondition(new QueryCondition("alias", RelationalOperator.LIKE, keyAliasFilterPattern));
        }


        logger.debug("Querying token entries for worker: " + workerId);
        try {
            var response = (JAXBElement<QueryTokenEntriesResponse>) getWebServiceTemplate().marshalSendAndReceive(
                    request);
            return response.getValue().getReturn();
        } catch (Exception e) {
            throw new RemoteSystemException("Failed to query token entries of worker " + workerId, e);
        }
    }

    public void importCertificateChain(int workerId, String keyAlias, List<byte[]> chain) {
        var request = new ImportCertificateChain();
        request.setWorkerId(workerId);
        request.setAlias(keyAlias);
        request.setCertificateChain(
                chain.stream().map(data -> Base64.getEncoder().encode(data)).map(String::new).toList());

        logger.debug("Importing certificate chain to crypto token " + workerId + " and key alias: " + keyAlias);
        try {
            getWebServiceTemplate().marshalSendAndReceive(request);
        } catch (Exception e) {
            throw new RemoteSystemException("Failed to import certificate chain for key " + keyAlias, e);
        }
    }

    public String generateKey(int workerId, String keyAlias, String keyAlgorithm, String keySpec) {
        var request = new GenerateSignerKey();
        request.setSignerId(workerId);
        request.setAlias(keyAlias);
        request.setKeyAlgorithm(keyAlgorithm);
        request.setKeySpec(keySpec);

        logger.debug("Generating new key " + keyAlias + " for crypto token " + workerId);
        try {
            var response = (JAXBElement<GenerateSignerKeyResponse>) getWebServiceTemplate().marshalSendAndReceive(
                    request);
            keyAlias = response.getValue().getReturn();
            logger.info("Generated key " + keyAlias + " for crypto token " + workerId);
            return keyAlias;
        } catch (Exception e) {
            throw new RemoteSystemException("Failed to generate new key " + keyAlias + " from crypto token " + workerId,
                                            e
            );
        }
    }

    public boolean removeKey(int workerId, String keyAlias) {
        var request = new RemoveKey();
        request.setSignerId(workerId);
        request.setAlias(keyAlias);

        logger.debug("Removing key " + keyAlias + " from crypto token " + workerId);
        try {
            var response = (JAXBElement<RemoveKeyResponse>) getWebServiceTemplate().marshalSendAndReceive(request);
            return response.getValue().isReturn();
        } catch (Exception e) {
            throw new RemoteSystemException("Failed to remove key " + keyAlias + " from crypto token " + workerId, e);
        }
    }
}