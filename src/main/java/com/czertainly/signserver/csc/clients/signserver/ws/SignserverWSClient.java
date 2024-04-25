package com.czertainly.signserver.csc.clients.signserver.ws;

import com.czertainly.signserver.csc.clients.signserver.ws.dto.*;
import jakarta.xml.bind.JAXBElement;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.ws.client.core.support.WebServiceGatewaySupport;
import org.springframework.ws.transport.http.HttpComponentsMessageSender;

import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;

public class SignserverWSClient extends WebServiceGatewaySupport {

    private static final Logger logger = LoggerFactory.getLogger(SignserverWSClient.class);

    public static final String WEB_SERVICE_BASE_PATH = "/signserver/AdminWSService/AdminWS";

    public SignserverWSClient(String signserverUrl) {
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
//        request.addCondition(new QueryCondition("alias", RelationalOperator.LIKE, "pregenerated___%"));


        logger.info("Querying token entries for worker: " + workerId);
        var response = (JAXBElement<QueryTokenEntriesResponse>) getWebServiceTemplate().marshalSendAndReceive(request);
        return response.getValue();
    }

    public static void main(String[] args
    ) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream keyStoreInputStream = new FileInputStream("/home/lukas/dev/customers/3key/lukas.najman.p12")) {
            keyStore.load(keyStoreInputStream, "lukas.najman".toCharArray());
        }

        SSLContext sslContext = SSLContexts.custom()
                                           .loadKeyMaterial(keyStore, "lukas.najman".toCharArray())
                                           .build();

        CloseableHttpClient httpClient = HttpClients.custom()
                                                    .setSSLContext(sslContext)
                                                    .addInterceptorFirst(
                                                            new HttpComponentsMessageSender.RemoveSoapHeadersInterceptor())
                                                    .build();

        HttpComponentsMessageSender httpComponentsMessageSender = new HttpComponentsMessageSender(httpClient);


        Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
        // this package must match the package in the <generatePackage> specified in
        // pom.xml
        marshaller.setContextPath("com.czertainly.signserver.csc.clients.signserver.ws.dto");
        SignserverWSClient client = new SignserverWSClient("https://signserver.3key.company");
        client.setMessageSender(httpComponentsMessageSender);
        client.setMarshaller(marshaller);
        client.setUnmarshaller(marshaller);
//        client.generateCsr(2, "pregenerated___-9modEPydhWleTPW6Yb6u-db7xI", "SHA512WithRSA", "CN=Test");
        var entries = client.queryTokenEntries(2, true, 0, 10);
        entries.getReturn().getEntries().forEach(entry -> {
            System.out.println(entry.getAlias());
        });
    }

}
