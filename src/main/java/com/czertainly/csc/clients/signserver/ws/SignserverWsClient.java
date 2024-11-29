package com.czertainly.csc.clients.signserver.ws;

import com.czertainly.csc.clients.signserver.ws.dto.*;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
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

    public Result<CertReqData, TextError> generateCsr(
            int workerId, String keyAlias, String signatureAlgorithm, String dn
    ) {

        var request = new GetPKCS10CertificateRequestForAlias2();
        var certReqInfo = new Pkcs10CertReqInfo();

        certReqInfo.setSignatureAlgorithm(signatureAlgorithm);
        certReqInfo.setSubjectDN(dn);

        request.setSignerId(workerId);
        request.setKeyAlias(keyAlias);
        request.setCertReqInfo(certReqInfo);

        logger.debug("Requesting CSR for key '{}' from crypto token with ID '{}'", keyAlias, workerId);
        try {
            var response = (JAXBElement<GetPKCS10CertificateRequestForAlias2Response>) getWebServiceTemplate()
                    .marshalSendAndReceive(request);
            var csrData = response.getValue().getReturn();
            logger.info("CSR was generated for key {}", keyAlias);
            return Result.success(csrData);
        } catch (Exception e) {
            logger.debug("Failed to generate CSR. Worker ID={}, KeyAlias={}, SignatureAlgorithm={}, DN={}",
                         workerId, keyAlias, signatureAlgorithm, dn, e
            );
            return Result.error(TextError.of(""));
        }
    }

    public Result<TokenSearchResults, TextError> queryTokenEntries(int workerId, boolean includeData, int startIndex,
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


        logger.debug("Querying token entries for worker: '{}'", workerId);
        try {
            var response = (JAXBElement<QueryTokenEntriesResponse>) getWebServiceTemplate().marshalSendAndReceive(
                    request);
            var results = response.getValue().getReturn();
            return Result.success(results);
        } catch (Exception e) {
            logger.debug("Failed to query token entries of worker {}", workerId, e);
            return Result.error(TextError.of(e));
        }
    }

    public Result<Void, TextError> importCertificateChain(int workerId, String keyAlias, List<byte[]> chain) {
        var request = new ImportCertificateChain();
        request.setWorkerId(workerId);
        request.setAlias(keyAlias);
        request.setCertificateChain(
                chain.stream().map(data -> Base64.getEncoder().encode(data)).map(String::new).toList());

        logger.debug("Importing certificate chain to key '{}' stored in crypto token with ID '{}'", keyAlias, workerId);
        try {
            getWebServiceTemplate().marshalSendAndReceive(request);
            logger.info("Certificate chain was imported to key '{}' stored in crypto token with ID '{}'", keyAlias,
                        workerId
            );
            return Result.emptySuccess();
        } catch (Exception e) {
            return Result.error(TextError.of(e));
        }
    }

    public Result<String, TextError> generateKey(int workerId, String keyAlias,
                                                 String keyAlgorithm, String keySpec
    ) {
        var request = new GenerateSignerKey();
        request.setSignerId(workerId);
        request.setAlias(keyAlias);
        request.setKeyAlgorithm(keyAlgorithm);
        request.setKeySpec(keySpec);

        logger.debug("Generating new key '{}' for crypto token '{}'", keyAlias, workerId);
        try {
            var response = (JAXBElement<GenerateSignerKeyResponse>) getWebServiceTemplate().marshalSendAndReceive(
                    request);
            keyAlias = response.getValue().getReturn();
            logger.info("A new key '{}' was generated for Crypto Token with ID '{}'", keyAlias, workerId);
            return Result.success(keyAlias);
        } catch (Exception e) {
            logger.error("Generation of a key '{}' on Crypto Token with ID '{}' has failed.", keyAlias, workerId, e);
            return Result.error(TextError.of(e));
        }
    }

    public Result<Void, TextError> removeKey(int workerId, String keyAlias, boolean notExistsOk) {
        var request = new RemoveKey();
        request.setSignerId(workerId);
        request.setAlias(keyAlias);

        logger.debug("Removing key '{}' from crypto token '{}'", keyAlias, workerId);
        try {
            var response = (JAXBElement<RemoveKeyResponse>) getWebServiceTemplate().marshalSendAndReceive(request);
            boolean isDeleted = response.getValue().isReturn();
            if (isDeleted) {
                logger.info("Key '{}' was removed from crypto token '{}'", keyAlias, workerId);
                return Result.emptySuccess();
            } else {
                return Result.error(TextError.of("Key '%s' was not removed but no error was returned.", keyAlias));
            }
        } catch (Exception e) {
            if (notExistsOk && e.getMessage().contains("No such alias in token")) {
                logger.info("Key '{}' was not found on crypto token '{}'. Key is considered removed.", keyAlias, workerId);
                return Result.emptySuccess();
            }
            logger.error("Failed to remove key '{}' from crypto token '{}'", keyAlias, workerId, e);
            return Result.error(TextError.of(e));
        }
    }
}