
package com.czertainly.signserver.csc.clients.signserver.ws.dto;

import javax.xml.namespace.QName;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.annotation.XmlElementDecl;
import jakarta.xml.bind.annotation.XmlRegistry;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the com.czertainly.signserver.csc.ws.signserver package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {

    private final static QName _ActivateSigner_QNAME = new QName("http://adminws.signserver.org/", "activateSigner");
    private final static QName _ActivateSignerResponse_QNAME = new QName("http://adminws.signserver.org/", "activateSignerResponse");
    private final static QName _AddAuthorizedClient_QNAME = new QName("http://adminws.signserver.org/", "addAuthorizedClient");
    private final static QName _AddAuthorizedClientResponse_QNAME = new QName("http://adminws.signserver.org/", "addAuthorizedClientResponse");
    private final static QName _DeactivateSigner_QNAME = new QName("http://adminws.signserver.org/", "deactivateSigner");
    private final static QName _DeactivateSignerResponse_QNAME = new QName("http://adminws.signserver.org/", "deactivateSignerResponse");
    private final static QName _DestroyKey_QNAME = new QName("http://adminws.signserver.org/", "destroyKey");
    private final static QName _DestroyKeyResponse_QNAME = new QName("http://adminws.signserver.org/", "destroyKeyResponse");
    private final static QName _GenerateSignerKey_QNAME = new QName("http://adminws.signserver.org/", "generateSignerKey");
    private final static QName _GenerateSignerKeyResponse_QNAME = new QName("http://adminws.signserver.org/", "generateSignerKeyResponse");
    private final static QName _GetAuthorizedClients_QNAME = new QName("http://adminws.signserver.org/", "getAuthorizedClients");
    private final static QName _GetAuthorizedClientsResponse_QNAME = new QName("http://adminws.signserver.org/", "getAuthorizedClientsResponse");
    private final static QName _GetCurrentWorkerConfig_QNAME = new QName("http://adminws.signserver.org/", "getCurrentWorkerConfig");
    private final static QName _GetCurrentWorkerConfigResponse_QNAME = new QName("http://adminws.signserver.org/", "getCurrentWorkerConfigResponse");
    private final static QName _GetGlobalConfiguration_QNAME = new QName("http://adminws.signserver.org/", "getGlobalConfiguration");
    private final static QName _GetGlobalConfigurationResponse_QNAME = new QName("http://adminws.signserver.org/", "getGlobalConfigurationResponse");
    private final static QName _GetKeyUsageCounterValue_QNAME = new QName("http://adminws.signserver.org/", "getKeyUsageCounterValue");
    private final static QName _GetKeyUsageCounterValueResponse_QNAME = new QName("http://adminws.signserver.org/", "getKeyUsageCounterValueResponse");
    private final static QName _GetPKCS10CertificateRequest_QNAME = new QName("http://adminws.signserver.org/", "getPKCS10CertificateRequest");
    private final static QName _GetPKCS10CertificateRequestForAlias_QNAME = new QName("http://adminws.signserver.org/", "getPKCS10CertificateRequestForAlias");
    private final static QName _GetPKCS10CertificateRequestForAlias2_QNAME = new QName("http://adminws.signserver.org/", "getPKCS10CertificateRequestForAlias2");
    private final static QName _GetPKCS10CertificateRequestForAlias2Response_QNAME = new QName("http://adminws.signserver.org/", "getPKCS10CertificateRequestForAlias2Response");
    private final static QName _GetPKCS10CertificateRequestForAliasResponse_QNAME = new QName("http://adminws.signserver.org/", "getPKCS10CertificateRequestForAliasResponse");
    private final static QName _GetPKCS10CertificateRequestForKey_QNAME = new QName("http://adminws.signserver.org/", "getPKCS10CertificateRequestForKey");
    private final static QName _GetPKCS10CertificateRequestForKey2_QNAME = new QName("http://adminws.signserver.org/", "getPKCS10CertificateRequestForKey2");
    private final static QName _GetPKCS10CertificateRequestForKey2Response_QNAME = new QName("http://adminws.signserver.org/", "getPKCS10CertificateRequestForKey2Response");
    private final static QName _GetPKCS10CertificateRequestForKeyResponse_QNAME = new QName("http://adminws.signserver.org/", "getPKCS10CertificateRequestForKeyResponse");
    private final static QName _GetPKCS10CertificateRequestResponse_QNAME = new QName("http://adminws.signserver.org/", "getPKCS10CertificateRequestResponse");
    private final static QName _GetSignerCertificate_QNAME = new QName("http://adminws.signserver.org/", "getSignerCertificate");
    private final static QName _GetSignerCertificateChain_QNAME = new QName("http://adminws.signserver.org/", "getSignerCertificateChain");
    private final static QName _GetSignerCertificateChainResponse_QNAME = new QName("http://adminws.signserver.org/", "getSignerCertificateChainResponse");
    private final static QName _GetSignerCertificateResponse_QNAME = new QName("http://adminws.signserver.org/", "getSignerCertificateResponse");
    private final static QName _GetSigningValidityNotAfter_QNAME = new QName("http://adminws.signserver.org/", "getSigningValidityNotAfter");
    private final static QName _GetSigningValidityNotAfterResponse_QNAME = new QName("http://adminws.signserver.org/", "getSigningValidityNotAfterResponse");
    private final static QName _GetSigningValidityNotBefore_QNAME = new QName("http://adminws.signserver.org/", "getSigningValidityNotBefore");
    private final static QName _GetSigningValidityNotBeforeResponse_QNAME = new QName("http://adminws.signserver.org/", "getSigningValidityNotBeforeResponse");
    private final static QName _GetStatus_QNAME = new QName("http://adminws.signserver.org/", "getStatus");
    private final static QName _GetStatusResponse_QNAME = new QName("http://adminws.signserver.org/", "getStatusResponse");
    private final static QName _GetWorkerId_QNAME = new QName("http://adminws.signserver.org/", "getWorkerId");
    private final static QName _GetWorkerIdResponse_QNAME = new QName("http://adminws.signserver.org/", "getWorkerIdResponse");
    private final static QName _GetWorkers_QNAME = new QName("http://adminws.signserver.org/", "getWorkers");
    private final static QName _GetWorkersResponse_QNAME = new QName("http://adminws.signserver.org/", "getWorkersResponse");
    private final static QName _GlobalReload_QNAME = new QName("http://adminws.signserver.org/", "globalReload");
    private final static QName _GlobalReloadResponse_QNAME = new QName("http://adminws.signserver.org/", "globalReloadResponse");
    private final static QName _GlobalResync_QNAME = new QName("http://adminws.signserver.org/", "globalResync");
    private final static QName _GlobalResyncResponse_QNAME = new QName("http://adminws.signserver.org/", "globalResyncResponse");
    private final static QName _ImportCertificateChain_QNAME = new QName("http://adminws.signserver.org/", "importCertificateChain");
    private final static QName _ImportCertificateChainResponse_QNAME = new QName("http://adminws.signserver.org/", "importCertificateChainResponse");
    private final static QName _Process_QNAME = new QName("http://adminws.signserver.org/", "process");
    private final static QName _ProcessResponse_QNAME = new QName("http://adminws.signserver.org/", "processResponse");
    private final static QName _QueryArchive_QNAME = new QName("http://adminws.signserver.org/", "queryArchive");
    private final static QName _QueryArchiveResponse_QNAME = new QName("http://adminws.signserver.org/", "queryArchiveResponse");
    private final static QName _QueryArchiveWithIds_QNAME = new QName("http://adminws.signserver.org/", "queryArchiveWithIds");
    private final static QName _QueryArchiveWithIdsResponse_QNAME = new QName("http://adminws.signserver.org/", "queryArchiveWithIdsResponse");
    private final static QName _QueryAuditLog_QNAME = new QName("http://adminws.signserver.org/", "queryAuditLog");
    private final static QName _QueryAuditLogResponse_QNAME = new QName("http://adminws.signserver.org/", "queryAuditLogResponse");
    private final static QName _QueryTokenEntries_QNAME = new QName("http://adminws.signserver.org/", "queryTokenEntries");
    private final static QName _QueryTokenEntriesResponse_QNAME = new QName("http://adminws.signserver.org/", "queryTokenEntriesResponse");
    private final static QName _ReloadConfiguration_QNAME = new QName("http://adminws.signserver.org/", "reloadConfiguration");
    private final static QName _ReloadConfigurationResponse_QNAME = new QName("http://adminws.signserver.org/", "reloadConfigurationResponse");
    private final static QName _RemoveAuthorizedClient_QNAME = new QName("http://adminws.signserver.org/", "removeAuthorizedClient");
    private final static QName _RemoveAuthorizedClientResponse_QNAME = new QName("http://adminws.signserver.org/", "removeAuthorizedClientResponse");
    private final static QName _RemoveGlobalProperty_QNAME = new QName("http://adminws.signserver.org/", "removeGlobalProperty");
    private final static QName _RemoveGlobalPropertyResponse_QNAME = new QName("http://adminws.signserver.org/", "removeGlobalPropertyResponse");
    private final static QName _RemoveKey_QNAME = new QName("http://adminws.signserver.org/", "removeKey");
    private final static QName _RemoveKeyResponse_QNAME = new QName("http://adminws.signserver.org/", "removeKeyResponse");
    private final static QName _RemoveWorkerProperty_QNAME = new QName("http://adminws.signserver.org/", "removeWorkerProperty");
    private final static QName _RemoveWorkerPropertyResponse_QNAME = new QName("http://adminws.signserver.org/", "removeWorkerPropertyResponse");
    private final static QName _SetGlobalProperty_QNAME = new QName("http://adminws.signserver.org/", "setGlobalProperty");
    private final static QName _SetGlobalPropertyResponse_QNAME = new QName("http://adminws.signserver.org/", "setGlobalPropertyResponse");
    private final static QName _SetWorkerProperty_QNAME = new QName("http://adminws.signserver.org/", "setWorkerProperty");
    private final static QName _SetWorkerPropertyResponse_QNAME = new QName("http://adminws.signserver.org/", "setWorkerPropertyResponse");
    private final static QName _TestKey_QNAME = new QName("http://adminws.signserver.org/", "testKey");
    private final static QName _TestKeyResponse_QNAME = new QName("http://adminws.signserver.org/", "testKeyResponse");
    private final static QName _UploadSignerCertificate_QNAME = new QName("http://adminws.signserver.org/", "uploadSignerCertificate");
    private final static QName _UploadSignerCertificateChain_QNAME = new QName("http://adminws.signserver.org/", "uploadSignerCertificateChain");
    private final static QName _UploadSignerCertificateChainResponse_QNAME = new QName("http://adminws.signserver.org/", "uploadSignerCertificateChainResponse");
    private final static QName _UploadSignerCertificateResponse_QNAME = new QName("http://adminws.signserver.org/", "uploadSignerCertificateResponse");
    private final static QName _InvalidWorkerIdException_QNAME = new QName("http://adminws.signserver.org/", "InvalidWorkerIdException");
    private final static QName _AdminNotAuthorizedException_QNAME = new QName("http://adminws.signserver.org/", "AdminNotAuthorizedException");
    private final static QName _SignServerException_QNAME = new QName("http://adminws.signserver.org/", "SignServerException");
    private final static QName _CryptoTokenOfflineException_QNAME = new QName("http://adminws.signserver.org/", "CryptoTokenOfflineException");
    private final static QName _OperationUnsupportedException_QNAME = new QName("http://adminws.signserver.org/", "OperationUnsupportedException");
    private final static QName _CertificateException_QNAME = new QName("http://adminws.signserver.org/", "CertificateException");
    private final static QName _KeyStoreException_QNAME = new QName("http://adminws.signserver.org/", "KeyStoreException");
    private final static QName _AuthorizationDeniedException_QNAME = new QName("http://adminws.signserver.org/", "AuthorizationDeniedException");
    private final static QName _QueryException_QNAME = new QName("http://adminws.signserver.org/", "QueryException");
    private final static QName _IllegalRequestException_QNAME = new QName("http://adminws.signserver.org/", "IllegalRequestException");
    private final static QName _CryptoTokenAuthenticationFailureException_QNAME = new QName("http://adminws.signserver.org/", "CryptoTokenAuthenticationFailureException");
    private final static QName _ResyncException_QNAME = new QName("http://adminws.signserver.org/", "ResyncException");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: com.czertainly.signserver.csc.ws.signserver
     * 
     */
    public ObjectFactory() {
    }

//    /**
//     * Create an instance of {@link WsWorkerConfig }
//     *
//     */
//    public WsWorkerConfig createWsWorkerConfig() {
//        return new WsWorkerConfig();
//    }
//
//    /**
//     * Create an instance of {@link WsWorkerConfig.Properties }
//     *
//     */
//    public WsWorkerConfig.Properties createWsWorkerConfigProperties() {
//        return new WsWorkerConfig.Properties();
//    }
//
//    /**
//     * Create an instance of {@link WsGlobalConfiguration }
//     *
//     */
//    public WsGlobalConfiguration createWsGlobalConfiguration() {
//        return new WsGlobalConfiguration();
//    }
//
//    /**
//     * Create an instance of {@link WsGlobalConfiguration.Config }
//     *
//     */
//    public WsGlobalConfiguration.Config createWsGlobalConfigurationConfig() {
//        return new WsGlobalConfiguration.Config();
//    }
//
//    /**
//     * Create an instance of {@link TokenEntry }
//     *
//     */
//    public TokenEntry createTokenEntry() {
//        return new TokenEntry();
//    }
//
//    /**
//     * Create an instance of {@link TokenEntry.Info }
//     *
//     */
//    public TokenEntry.Info createTokenEntryInfo() {
//        return new TokenEntry.Info();
//    }
//
//    /**
//     * Create an instance of {@link LogEntry }
//     *
//     */
//    public LogEntry createLogEntry() {
//        return new LogEntry();
//    }
//
//    /**
//     * Create an instance of {@link LogEntry.AdditionalDetails }
//     *
//     */
//    public LogEntry.AdditionalDetails createLogEntryAdditionalDetails() {
//        return new LogEntry.AdditionalDetails();
//    }
//
//    /**
//     * Create an instance of {@link WsWorkerStatus }
//     *
//     */
//    public WsWorkerStatus createWsWorkerStatus() {
//        return new WsWorkerStatus();
//    }
//
//    /**
//     * Create an instance of {@link WsWorkerStatus.ActiveConfig }
//     *
//     */
//    public WsWorkerStatus.ActiveConfig createWsWorkerStatusActiveConfig() {
//        return new WsWorkerStatus.ActiveConfig();
//    }
//
//    /**
//     * Create an instance of {@link ActivateSigner }
//     *
//     */
//    public ActivateSigner createActivateSigner() {
//        return new ActivateSigner();
//    }
//
//    /**
//     * Create an instance of {@link ActivateSignerResponse }
//     *
//     */
//    public ActivateSignerResponse createActivateSignerResponse() {
//        return new ActivateSignerResponse();
//    }
//
//    /**
//     * Create an instance of {@link AddAuthorizedClient }
//     *
//     */
//    public AddAuthorizedClient createAddAuthorizedClient() {
//        return new AddAuthorizedClient();
//    }
//
//    /**
//     * Create an instance of {@link AddAuthorizedClientResponse }
//     *
//     */
//    public AddAuthorizedClientResponse createAddAuthorizedClientResponse() {
//        return new AddAuthorizedClientResponse();
//    }
//
//    /**
//     * Create an instance of {@link DeactivateSigner }
//     *
//     */
//    public DeactivateSigner createDeactivateSigner() {
//        return new DeactivateSigner();
//    }
//
//    /**
//     * Create an instance of {@link DeactivateSignerResponse }
//     *
//     */
//    public DeactivateSignerResponse createDeactivateSignerResponse() {
//        return new DeactivateSignerResponse();
//    }
//
//    /**
//     * Create an instance of {@link DestroyKey }
//     *
//     */
//    public DestroyKey createDestroyKey() {
//        return new DestroyKey();
//    }
//
//    /**
//     * Create an instance of {@link DestroyKeyResponse }
//     *
//     */
//    public DestroyKeyResponse createDestroyKeyResponse() {
//        return new DestroyKeyResponse();
//    }
//
//    /**
//     * Create an instance of {@link GenerateSignerKey }
//     *
//     */
//    public GenerateSignerKey createGenerateSignerKey() {
//        return new GenerateSignerKey();
//    }
//
//    /**
//     * Create an instance of {@link GenerateSignerKeyResponse }
//     *
//     */
//    public GenerateSignerKeyResponse createGenerateSignerKeyResponse() {
//        return new GenerateSignerKeyResponse();
//    }
//
//    /**
//     * Create an instance of {@link GetAuthorizedClients }
//     *
//     */
//    public GetAuthorizedClients createGetAuthorizedClients() {
//        return new GetAuthorizedClients();
//    }
//
//    /**
//     * Create an instance of {@link GetAuthorizedClientsResponse }
//     *
//     */
//    public GetAuthorizedClientsResponse createGetAuthorizedClientsResponse() {
//        return new GetAuthorizedClientsResponse();
//    }
//
//    /**
//     * Create an instance of {@link GetCurrentWorkerConfig }
//     *
//     */
//    public GetCurrentWorkerConfig createGetCurrentWorkerConfig() {
//        return new GetCurrentWorkerConfig();
//    }
//
//    /**
//     * Create an instance of {@link GetCurrentWorkerConfigResponse }
//     *
//     */
//    public GetCurrentWorkerConfigResponse createGetCurrentWorkerConfigResponse() {
//        return new GetCurrentWorkerConfigResponse();
//    }
//
//    /**
//     * Create an instance of {@link GetGlobalConfiguration }
//     *
//     */
//    public GetGlobalConfiguration createGetGlobalConfiguration() {
//        return new GetGlobalConfiguration();
//    }
//
//    /**
//     * Create an instance of {@link GetGlobalConfigurationResponse }
//     *
//     */
//    public GetGlobalConfigurationResponse createGetGlobalConfigurationResponse() {
//        return new GetGlobalConfigurationResponse();
//    }
//
//    /**
//     * Create an instance of {@link GetKeyUsageCounterValue }
//     *
//     */
//    public GetKeyUsageCounterValue createGetKeyUsageCounterValue() {
//        return new GetKeyUsageCounterValue();
//    }
//
//    /**
//     * Create an instance of {@link GetKeyUsageCounterValueResponse }
//     *
//     */
//    public GetKeyUsageCounterValueResponse createGetKeyUsageCounterValueResponse() {
//        return new GetKeyUsageCounterValueResponse();
//    }
//
//    /**
//     * Create an instance of {@link GetPKCS10CertificateRequest }
//     *
//     */
//    public GetPKCS10CertificateRequest createGetPKCS10CertificateRequest() {
//        return new GetPKCS10CertificateRequest();
//    }
//
//    /**
//     * Create an instance of {@link GetPKCS10CertificateRequestForAlias }
//     *
//     */
//    public GetPKCS10CertificateRequestForAlias createGetPKCS10CertificateRequestForAlias() {
//        return new GetPKCS10CertificateRequestForAlias();
//    }

    /**
     * Create an instance of {@link GetPKCS10CertificateRequestForAlias2 }
     * 
     */
    public GetPKCS10CertificateRequestForAlias2 createGetPKCS10CertificateRequestForAlias2() {
        return new GetPKCS10CertificateRequestForAlias2();
    }

    /**
     * Create an instance of {@link GetPKCS10CertificateRequestForAlias2Response }
     * 
     */
    public GetPKCS10CertificateRequestForAlias2Response createGetPKCS10CertificateRequestForAlias2Response() {
        return new GetPKCS10CertificateRequestForAlias2Response();
    }

//    /**
//     * Create an instance of {@link GetPKCS10CertificateRequestForAliasResponse }
//     *
//     */
//    public GetPKCS10CertificateRequestForAliasResponse createGetPKCS10CertificateRequestForAliasResponse() {
//        return new GetPKCS10CertificateRequestForAliasResponse();
//    }
//
//    /**
//     * Create an instance of {@link GetPKCS10CertificateRequestForKey }
//     *
//     */
//    public GetPKCS10CertificateRequestForKey createGetPKCS10CertificateRequestForKey() {
//        return new GetPKCS10CertificateRequestForKey();
//    }
//
//    /**
//     * Create an instance of {@link GetPKCS10CertificateRequestForKey2 }
//     *
//     */
//    public GetPKCS10CertificateRequestForKey2 createGetPKCS10CertificateRequestForKey2() {
//        return new GetPKCS10CertificateRequestForKey2();
//    }
//
//    /**
//     * Create an instance of {@link GetPKCS10CertificateRequestForKey2Response }
//     *
//     */
//    public GetPKCS10CertificateRequestForKey2Response createGetPKCS10CertificateRequestForKey2Response() {
//        return new GetPKCS10CertificateRequestForKey2Response();
//    }
//
//    /**
//     * Create an instance of {@link GetPKCS10CertificateRequestForKeyResponse }
//     *
//     */
//    public GetPKCS10CertificateRequestForKeyResponse createGetPKCS10CertificateRequestForKeyResponse() {
//        return new GetPKCS10CertificateRequestForKeyResponse();
//    }
//
//    /**
//     * Create an instance of {@link GetPKCS10CertificateRequestResponse }
//     *
//     */
//    public GetPKCS10CertificateRequestResponse createGetPKCS10CertificateRequestResponse() {
//        return new GetPKCS10CertificateRequestResponse();
//    }
//
//    /**
//     * Create an instance of {@link GetSignerCertificate }
//     *
//     */
//    public GetSignerCertificate createGetSignerCertificate() {
//        return new GetSignerCertificate();
//    }
//
//    /**
//     * Create an instance of {@link GetSignerCertificateChain }
//     *
//     */
//    public GetSignerCertificateChain createGetSignerCertificateChain() {
//        return new GetSignerCertificateChain();
//    }
//
//    /**
//     * Create an instance of {@link GetSignerCertificateChainResponse }
//     *
//     */
//    public GetSignerCertificateChainResponse createGetSignerCertificateChainResponse() {
//        return new GetSignerCertificateChainResponse();
//    }
//
//    /**
//     * Create an instance of {@link GetSignerCertificateResponse }
//     *
//     */
//    public GetSignerCertificateResponse createGetSignerCertificateResponse() {
//        return new GetSignerCertificateResponse();
//    }
//
//    /**
//     * Create an instance of {@link GetSigningValidityNotAfter }
//     *
//     */
//    public GetSigningValidityNotAfter createGetSigningValidityNotAfter() {
//        return new GetSigningValidityNotAfter();
//    }
//
//    /**
//     * Create an instance of {@link GetSigningValidityNotAfterResponse }
//     *
//     */
//    public GetSigningValidityNotAfterResponse createGetSigningValidityNotAfterResponse() {
//        return new GetSigningValidityNotAfterResponse();
//    }
//
//    /**
//     * Create an instance of {@link GetSigningValidityNotBefore }
//     *
//     */
//    public GetSigningValidityNotBefore createGetSigningValidityNotBefore() {
//        return new GetSigningValidityNotBefore();
//    }
//
//    /**
//     * Create an instance of {@link GetSigningValidityNotBeforeResponse }
//     *
//     */
//    public GetSigningValidityNotBeforeResponse createGetSigningValidityNotBeforeResponse() {
//        return new GetSigningValidityNotBeforeResponse();
//    }
//
//    /**
//     * Create an instance of {@link GetStatus }
//     *
//     */
//    public GetStatus createGetStatus() {
//        return new GetStatus();
//    }
//
//    /**
//     * Create an instance of {@link GetStatusResponse }
//     *
//     */
//    public GetStatusResponse createGetStatusResponse() {
//        return new GetStatusResponse();
//    }
//
//    /**
//     * Create an instance of {@link GetWorkerId }
//     *
//     */
//    public GetWorkerId createGetWorkerId() {
//        return new GetWorkerId();
//    }
//
//    /**
//     * Create an instance of {@link GetWorkerIdResponse }
//     *
//     */
//    public GetWorkerIdResponse createGetWorkerIdResponse() {
//        return new GetWorkerIdResponse();
//    }
//
//    /**
//     * Create an instance of {@link GetWorkers }
//     *
//     */
//    public GetWorkers createGetWorkers() {
//        return new GetWorkers();
//    }
//
//    /**
//     * Create an instance of {@link GetWorkersResponse }
//     *
//     */
//    public GetWorkersResponse createGetWorkersResponse() {
//        return new GetWorkersResponse();
//    }
//
//    /**
//     * Create an instance of {@link GlobalReload }
//     *
//     */
//    public GlobalReload createGlobalReload() {
//        return new GlobalReload();
//    }
//
//    /**
//     * Create an instance of {@link GlobalReloadResponse }
//     *
//     */
//    public GlobalReloadResponse createGlobalReloadResponse() {
//        return new GlobalReloadResponse();
//    }
//
//    /**
//     * Create an instance of {@link GlobalResync }
//     *
//     */
//    public GlobalResync createGlobalResync() {
//        return new GlobalResync();
//    }
//
//    /**
//     * Create an instance of {@link GlobalResyncResponse }
//     *
//     */
//    public GlobalResyncResponse createGlobalResyncResponse() {
//        return new GlobalResyncResponse();
//    }
//
    /**
     * Create an instance of {@link ImportCertificateChain }
     *
     */
    public ImportCertificateChain createImportCertificateChain() {
        return new ImportCertificateChain();
    }

    /**
     * Create an instance of {@link ImportCertificateChainResponse }
     *
     */
    public ImportCertificateChainResponse createImportCertificateChainResponse() {
        return new ImportCertificateChainResponse();
    }

//    /**
//     * Create an instance of {@link Process }
//     *
//     */
//    public Process createProcess() {
//        return new Process();
//    }
//
//    /**
//     * Create an instance of {@link ProcessResponse }
//     *
//     */
//    public ProcessResponse createProcessResponse() {
//        return new ProcessResponse();
//    }
//
//    /**
//     * Create an instance of {@link QueryArchive }
//     *
//     */
//    public QueryArchive createQueryArchive() {
//        return new QueryArchive();
//    }
//
//    /**
//     * Create an instance of {@link QueryArchiveResponse }
//     *
//     */
//    public QueryArchiveResponse createQueryArchiveResponse() {
//        return new QueryArchiveResponse();
//    }
//
//    /**
//     * Create an instance of {@link QueryArchiveWithIds }
//     *
//     */
//    public QueryArchiveWithIds createQueryArchiveWithIds() {
//        return new QueryArchiveWithIds();
//    }
//
//    /**
//     * Create an instance of {@link QueryArchiveWithIdsResponse }
//     *
//     */
//    public QueryArchiveWithIdsResponse createQueryArchiveWithIdsResponse() {
//        return new QueryArchiveWithIdsResponse();
//    }
//
//    /**
//     * Create an instance of {@link QueryAuditLog }
//     *
//     */
//    public QueryAuditLog createQueryAuditLog() {
//        return new QueryAuditLog();
//    }
//
//    /**
//     * Create an instance of {@link QueryAuditLogResponse }
//     *
//     */
//    public QueryAuditLogResponse createQueryAuditLogResponse() {
//        return new QueryAuditLogResponse();
//    }
//
//    /**
//     * Create an instance of {@link QueryTokenEntries }
//     *
//     */
//    public QueryTokenEntries createQueryTokenEntries() {
//        return new QueryTokenEntries();
//    }
//
//    /**
//     * Create an instance of {@link QueryTokenEntriesResponse }
//     *
//     */
//    public QueryTokenEntriesResponse createQueryTokenEntriesResponse() {
//        return new QueryTokenEntriesResponse();
//    }
//
//    /**
//     * Create an instance of {@link ReloadConfiguration }
//     *
//     */
//    public ReloadConfiguration createReloadConfiguration() {
//        return new ReloadConfiguration();
//    }
//
//    /**
//     * Create an instance of {@link ReloadConfigurationResponse }
//     *
//     */
//    public ReloadConfigurationResponse createReloadConfigurationResponse() {
//        return new ReloadConfigurationResponse();
//    }
//
//    /**
//     * Create an instance of {@link RemoveAuthorizedClient }
//     *
//     */
//    public RemoveAuthorizedClient createRemoveAuthorizedClient() {
//        return new RemoveAuthorizedClient();
//    }
//
//    /**
//     * Create an instance of {@link RemoveAuthorizedClientResponse }
//     *
//     */
//    public RemoveAuthorizedClientResponse createRemoveAuthorizedClientResponse() {
//        return new RemoveAuthorizedClientResponse();
//    }
//
//    /**
//     * Create an instance of {@link RemoveGlobalProperty }
//     *
//     */
//    public RemoveGlobalProperty createRemoveGlobalProperty() {
//        return new RemoveGlobalProperty();
//    }
//
//    /**
//     * Create an instance of {@link RemoveGlobalPropertyResponse }
//     *
//     */
//    public RemoveGlobalPropertyResponse createRemoveGlobalPropertyResponse() {
//        return new RemoveGlobalPropertyResponse();
//    }

    /**
     * Create an instance of {@link RemoveKey }
     *
     */
    public RemoveKey createRemoveKey() {
        return new RemoveKey();
    }

    /**
     * Create an instance of {@link RemoveKeyResponse }
     *
     */
    public RemoveKeyResponse createRemoveKeyResponse() {
        return new RemoveKeyResponse();
    }

//    /**
//     * Create an instance of {@link RemoveWorkerProperty }
//     *
//     */
//    public RemoveWorkerProperty createRemoveWorkerProperty() {
//        return new RemoveWorkerProperty();
//    }
//
//    /**
//     * Create an instance of {@link RemoveWorkerPropertyResponse }
//     *
//     */
//    public RemoveWorkerPropertyResponse createRemoveWorkerPropertyResponse() {
//        return new RemoveWorkerPropertyResponse();
//    }
//
//    /**
//     * Create an instance of {@link SetGlobalProperty }
//     *
//     */
//    public SetGlobalProperty createSetGlobalProperty() {
//        return new SetGlobalProperty();
//    }
//
//    /**
//     * Create an instance of {@link SetGlobalPropertyResponse }
//     *
//     */
//    public SetGlobalPropertyResponse createSetGlobalPropertyResponse() {
//        return new SetGlobalPropertyResponse();
//    }
//
//    /**
//     * Create an instance of {@link SetWorkerProperty }
//     *
//     */
//    public SetWorkerProperty createSetWorkerProperty() {
//        return new SetWorkerProperty();
//    }
//
//    /**
//     * Create an instance of {@link SetWorkerPropertyResponse }
//     *
//     */
//    public SetWorkerPropertyResponse createSetWorkerPropertyResponse() {
//        return new SetWorkerPropertyResponse();
//    }
//
//    /**
//     * Create an instance of {@link TestKey }
//     *
//     */
//    public TestKey createTestKey() {
//        return new TestKey();
//    }
//
//    /**
//     * Create an instance of {@link TestKeyResponse }
//     *
//     */
//    public TestKeyResponse createTestKeyResponse() {
//        return new TestKeyResponse();
//    }
//
//    /**
//     * Create an instance of {@link UploadSignerCertificate }
//     *
//     */
//    public UploadSignerCertificate createUploadSignerCertificate() {
//        return new UploadSignerCertificate();
//    }
//
//    /**
//     * Create an instance of {@link UploadSignerCertificateChain }
//     *
//     */
//    public UploadSignerCertificateChain createUploadSignerCertificateChain() {
//        return new UploadSignerCertificateChain();
//    }
//
//    /**
//     * Create an instance of {@link UploadSignerCertificateChainResponse }
//     *
//     */
//    public UploadSignerCertificateChainResponse createUploadSignerCertificateChainResponse() {
//        return new UploadSignerCertificateChainResponse();
//    }
//
//    /**
//     * Create an instance of {@link UploadSignerCertificateResponse }
//     *
//     */
//    public UploadSignerCertificateResponse createUploadSignerCertificateResponse() {
//        return new UploadSignerCertificateResponse();
//    }
//
//    /**
//     * Create an instance of {@link InvalidWorkerIdException }
//     *
//     */
//    public InvalidWorkerIdException createInvalidWorkerIdException() {
//        return new InvalidWorkerIdException();
//    }
//
//    /**
//     * Create an instance of {@link AdminNotAuthorizedException }
//     *
//     */
//    public AdminNotAuthorizedException createAdminNotAuthorizedException() {
//        return new AdminNotAuthorizedException();
//    }
//
//    /**
//     * Create an instance of {@link SignServerException }
//     *
//     */
//    public SignServerException createSignServerException() {
//        return new SignServerException();
//    }
//
//    /**
//     * Create an instance of {@link CryptoTokenOfflineException }
//     *
//     */
//    public CryptoTokenOfflineException createCryptoTokenOfflineException() {
//        return new CryptoTokenOfflineException();
//    }
//
//    /**
//     * Create an instance of {@link OperationUnsupportedException }
//     *
//     */
//    public OperationUnsupportedException createOperationUnsupportedException() {
//        return new OperationUnsupportedException();
//    }
//
//    /**
//     * Create an instance of {@link CertificateException }
//     *
//     */
//    public CertificateException createCertificateException() {
//        return new CertificateException();
//    }
//
//    /**
//     * Create an instance of {@link KeyStoreException }
//     *
//     */
//    public KeyStoreException createKeyStoreException() {
//        return new KeyStoreException();
//    }
//
//    /**
//     * Create an instance of {@link AuthorizationDeniedException }
//     *
//     */
//    public AuthorizationDeniedException createAuthorizationDeniedException() {
//        return new AuthorizationDeniedException();
//    }
//
//    /**
//     * Create an instance of {@link QueryException }
//     *
//     */
//    public QueryException createQueryException() {
//        return new QueryException();
//    }
//
//    /**
//     * Create an instance of {@link IllegalRequestException }
//     *
//     */
//    public IllegalRequestException createIllegalRequestException() {
//        return new IllegalRequestException();
//    }
//
//    /**
//     * Create an instance of {@link CryptoTokenAuthenticationFailureException }
//     *
//     */
//    public CryptoTokenAuthenticationFailureException createCryptoTokenAuthenticationFailureException() {
//        return new CryptoTokenAuthenticationFailureException();
//    }
//
//    /**
//     * Create an instance of {@link ResyncException }
//     *
//     */
//    public ResyncException createResyncException() {
//        return new ResyncException();
//    }
//
//    /**
//     * Create an instance of {@link ArchiveEntry }
//     *
//     */
//    public ArchiveEntry createArchiveEntry() {
//        return new ArchiveEntry();
//    }
//
//    /**
//     * Create an instance of {@link AuthorizedClient }
//     *
//     */
//    public AuthorizedClient createAuthorizedClient() {
//        return new AuthorizedClient();
//    }
//
//    /**
//     * Create an instance of {@link QueryCondition }
//     *
//     */
//    public QueryCondition createQueryCondition() {
//        return new QueryCondition();
//    }
//
//    /**
//     * Create an instance of {@link QueryOrdering }
//     *
//     */
//    public QueryOrdering createQueryOrdering() {
//        return new QueryOrdering();
//    }
//
//    /**
//     * Create an instance of {@link Pkcs10CertReqInfo }
//     *
//     */
//    public Pkcs10CertReqInfo createPkcs10CertReqInfo() {
//        return new Pkcs10CertReqInfo();
//    }
//
//    /**
//     * Create an instance of {@link CertReqData }
//     *
//     */
//    public CertReqData createCertReqData() {
//        return new CertReqData();
//    }
//
//    /**
//     * Create an instance of {@link Base64SignerCertReqData }
//     *
//     */
//    public Base64SignerCertReqData createBase64SignerCertReqData() {
//        return new Base64SignerCertReqData();
//    }
//
//    /**
//     * Create an instance of {@link KeyTestResult }
//     *
//     */
//    public KeyTestResult createKeyTestResult() {
//        return new KeyTestResult();
//    }
//
//    /**
//     * Create an instance of {@link TokenSearchResults }
//     *
//     */
//    public TokenSearchResults createTokenSearchResults() {
//        return new TokenSearchResults();
//    }
//
//    /**
//     * Create an instance of {@link WsWorkerConfig.Properties.Entry }
//     *
//     */
//    public WsWorkerConfig.Properties.Entry createWsWorkerConfigPropertiesEntry() {
//        return new WsWorkerConfig.Properties.Entry();
//    }
//
//    /**
//     * Create an instance of {@link WsGlobalConfiguration.Config.Entry }
//     *
//     */
//    public WsGlobalConfiguration.Config.Entry createWsGlobalConfigurationConfigEntry() {
//        return new WsGlobalConfiguration.Config.Entry();
//    }
//
//    /**
//     * Create an instance of {@link TokenEntry.Info.Entry }
//     *
//     */
//    public TokenEntry.Info.Entry createTokenEntryInfoEntry() {
//        return new TokenEntry.Info.Entry();
//    }
//
//    /**
//     * Create an instance of {@link LogEntry.AdditionalDetails.Entry }
//     *
//     */
//    public LogEntry.AdditionalDetails.Entry createLogEntryAdditionalDetailsEntry() {
//        return new LogEntry.AdditionalDetails.Entry();
//    }
//
//    /**
//     * Create an instance of {@link WsWorkerStatus.ActiveConfig.Entry }
//     *
//     */
//    public WsWorkerStatus.ActiveConfig.Entry createWsWorkerStatusActiveConfigEntry() {
//        return new WsWorkerStatus.ActiveConfig.Entry();
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link ActivateSigner }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link ActivateSigner }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "activateSigner")
//    public JAXBElement<ActivateSigner> createActivateSigner(ActivateSigner value) {
//        return new JAXBElement<ActivateSigner>(_ActivateSigner_QNAME, ActivateSigner.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link ActivateSignerResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link ActivateSignerResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "activateSignerResponse")
//    public JAXBElement<ActivateSignerResponse> createActivateSignerResponse(ActivateSignerResponse value) {
//        return new JAXBElement<ActivateSignerResponse>(_ActivateSignerResponse_QNAME, ActivateSignerResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link AddAuthorizedClient }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link AddAuthorizedClient }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "addAuthorizedClient")
//    public JAXBElement<AddAuthorizedClient> createAddAuthorizedClient(AddAuthorizedClient value) {
//        return new JAXBElement<AddAuthorizedClient>(_AddAuthorizedClient_QNAME, AddAuthorizedClient.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link AddAuthorizedClientResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link AddAuthorizedClientResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "addAuthorizedClientResponse")
//    public JAXBElement<AddAuthorizedClientResponse> createAddAuthorizedClientResponse(AddAuthorizedClientResponse value) {
//        return new JAXBElement<AddAuthorizedClientResponse>(_AddAuthorizedClientResponse_QNAME, AddAuthorizedClientResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link DeactivateSigner }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link DeactivateSigner }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "deactivateSigner")
//    public JAXBElement<DeactivateSigner> createDeactivateSigner(DeactivateSigner value) {
//        return new JAXBElement<DeactivateSigner>(_DeactivateSigner_QNAME, DeactivateSigner.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link DeactivateSignerResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link DeactivateSignerResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "deactivateSignerResponse")
//    public JAXBElement<DeactivateSignerResponse> createDeactivateSignerResponse(DeactivateSignerResponse value) {
//        return new JAXBElement<DeactivateSignerResponse>(_DeactivateSignerResponse_QNAME, DeactivateSignerResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link DestroyKey }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link DestroyKey }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "destroyKey")
//    public JAXBElement<DestroyKey> createDestroyKey(DestroyKey value) {
//        return new JAXBElement<DestroyKey>(_DestroyKey_QNAME, DestroyKey.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link DestroyKeyResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link DestroyKeyResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "destroyKeyResponse")
//    public JAXBElement<DestroyKeyResponse> createDestroyKeyResponse(DestroyKeyResponse value) {
//        return new JAXBElement<DestroyKeyResponse>(_DestroyKeyResponse_QNAME, DestroyKeyResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GenerateSignerKey }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GenerateSignerKey }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "generateSignerKey")
//    public JAXBElement<GenerateSignerKey> createGenerateSignerKey(GenerateSignerKey value) {
//        return new JAXBElement<GenerateSignerKey>(_GenerateSignerKey_QNAME, GenerateSignerKey.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GenerateSignerKeyResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GenerateSignerKeyResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "generateSignerKeyResponse")
//    public JAXBElement<GenerateSignerKeyResponse> createGenerateSignerKeyResponse(GenerateSignerKeyResponse value) {
//        return new JAXBElement<GenerateSignerKeyResponse>(_GenerateSignerKeyResponse_QNAME, GenerateSignerKeyResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetAuthorizedClients }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetAuthorizedClients }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getAuthorizedClients")
//    public JAXBElement<GetAuthorizedClients> createGetAuthorizedClients(GetAuthorizedClients value) {
//        return new JAXBElement<GetAuthorizedClients>(_GetAuthorizedClients_QNAME, GetAuthorizedClients.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetAuthorizedClientsResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetAuthorizedClientsResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getAuthorizedClientsResponse")
//    public JAXBElement<GetAuthorizedClientsResponse> createGetAuthorizedClientsResponse(GetAuthorizedClientsResponse value) {
//        return new JAXBElement<GetAuthorizedClientsResponse>(_GetAuthorizedClientsResponse_QNAME, GetAuthorizedClientsResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetCurrentWorkerConfig }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetCurrentWorkerConfig }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getCurrentWorkerConfig")
//    public JAXBElement<GetCurrentWorkerConfig> createGetCurrentWorkerConfig(GetCurrentWorkerConfig value) {
//        return new JAXBElement<GetCurrentWorkerConfig>(_GetCurrentWorkerConfig_QNAME, GetCurrentWorkerConfig.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetCurrentWorkerConfigResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetCurrentWorkerConfigResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getCurrentWorkerConfigResponse")
//    public JAXBElement<GetCurrentWorkerConfigResponse> createGetCurrentWorkerConfigResponse(GetCurrentWorkerConfigResponse value) {
//        return new JAXBElement<GetCurrentWorkerConfigResponse>(_GetCurrentWorkerConfigResponse_QNAME, GetCurrentWorkerConfigResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetGlobalConfiguration }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetGlobalConfiguration }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getGlobalConfiguration")
//    public JAXBElement<GetGlobalConfiguration> createGetGlobalConfiguration(GetGlobalConfiguration value) {
//        return new JAXBElement<GetGlobalConfiguration>(_GetGlobalConfiguration_QNAME, GetGlobalConfiguration.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetGlobalConfigurationResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetGlobalConfigurationResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getGlobalConfigurationResponse")
//    public JAXBElement<GetGlobalConfigurationResponse> createGetGlobalConfigurationResponse(GetGlobalConfigurationResponse value) {
//        return new JAXBElement<GetGlobalConfigurationResponse>(_GetGlobalConfigurationResponse_QNAME, GetGlobalConfigurationResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetKeyUsageCounterValue }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetKeyUsageCounterValue }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getKeyUsageCounterValue")
//    public JAXBElement<GetKeyUsageCounterValue> createGetKeyUsageCounterValue(GetKeyUsageCounterValue value) {
//        return new JAXBElement<GetKeyUsageCounterValue>(_GetKeyUsageCounterValue_QNAME, GetKeyUsageCounterValue.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetKeyUsageCounterValueResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetKeyUsageCounterValueResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getKeyUsageCounterValueResponse")
//    public JAXBElement<GetKeyUsageCounterValueResponse> createGetKeyUsageCounterValueResponse(GetKeyUsageCounterValueResponse value) {
//        return new JAXBElement<GetKeyUsageCounterValueResponse>(_GetKeyUsageCounterValueResponse_QNAME, GetKeyUsageCounterValueResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequest }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequest }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getPKCS10CertificateRequest")
//    public JAXBElement<GetPKCS10CertificateRequest> createGetPKCS10CertificateRequest(GetPKCS10CertificateRequest value) {
//        return new JAXBElement<GetPKCS10CertificateRequest>(_GetPKCS10CertificateRequest_QNAME, GetPKCS10CertificateRequest.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestForAlias }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestForAlias }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getPKCS10CertificateRequestForAlias")
//    public JAXBElement<GetPKCS10CertificateRequestForAlias> createGetPKCS10CertificateRequestForAlias(GetPKCS10CertificateRequestForAlias value) {
//        return new JAXBElement<GetPKCS10CertificateRequestForAlias>(_GetPKCS10CertificateRequestForAlias_QNAME, GetPKCS10CertificateRequestForAlias.class, null, value);
//    }
//
    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestForAlias2 }{@code >}
     *
     * @param value
     *     Java instance representing xml element's value.
     * @return
     *     the new instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestForAlias2 }{@code >}
     */
    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getPKCS10CertificateRequestForAlias2")
    public JAXBElement<GetPKCS10CertificateRequestForAlias2> createGetPKCS10CertificateRequestForAlias2(GetPKCS10CertificateRequestForAlias2 value) {
        return new JAXBElement<GetPKCS10CertificateRequestForAlias2>(_GetPKCS10CertificateRequestForAlias2_QNAME, GetPKCS10CertificateRequestForAlias2 .class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestForAlias2Response }{@code >}
     *
     * @param value
     *     Java instance representing xml element's value.
     * @return
     *     the new instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestForAlias2Response }{@code >}
     */
    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getPKCS10CertificateRequestForAlias2Response")
    public JAXBElement<GetPKCS10CertificateRequestForAlias2Response> createGetPKCS10CertificateRequestForAlias2Response(GetPKCS10CertificateRequestForAlias2Response value) {
        return new JAXBElement<GetPKCS10CertificateRequestForAlias2Response>(_GetPKCS10CertificateRequestForAlias2Response_QNAME, GetPKCS10CertificateRequestForAlias2Response.class, null, value);
    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestForAliasResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestForAliasResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getPKCS10CertificateRequestForAliasResponse")
//    public JAXBElement<GetPKCS10CertificateRequestForAliasResponse> createGetPKCS10CertificateRequestForAliasResponse(GetPKCS10CertificateRequestForAliasResponse value) {
//        return new JAXBElement<GetPKCS10CertificateRequestForAliasResponse>(_GetPKCS10CertificateRequestForAliasResponse_QNAME, GetPKCS10CertificateRequestForAliasResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestForKey }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestForKey }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getPKCS10CertificateRequestForKey")
//    public JAXBElement<GetPKCS10CertificateRequestForKey> createGetPKCS10CertificateRequestForKey(GetPKCS10CertificateRequestForKey value) {
//        return new JAXBElement<GetPKCS10CertificateRequestForKey>(_GetPKCS10CertificateRequestForKey_QNAME, GetPKCS10CertificateRequestForKey.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestForKey2 }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestForKey2 }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getPKCS10CertificateRequestForKey2")
//    public JAXBElement<GetPKCS10CertificateRequestForKey2> createGetPKCS10CertificateRequestForKey2(GetPKCS10CertificateRequestForKey2 value) {
//        return new JAXBElement<GetPKCS10CertificateRequestForKey2>(_GetPKCS10CertificateRequestForKey2_QNAME, GetPKCS10CertificateRequestForKey2 .class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestForKey2Response }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestForKey2Response }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getPKCS10CertificateRequestForKey2Response")
//    public JAXBElement<GetPKCS10CertificateRequestForKey2Response> createGetPKCS10CertificateRequestForKey2Response(GetPKCS10CertificateRequestForKey2Response value) {
//        return new JAXBElement<GetPKCS10CertificateRequestForKey2Response>(_GetPKCS10CertificateRequestForKey2Response_QNAME, GetPKCS10CertificateRequestForKey2Response.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestForKeyResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestForKeyResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getPKCS10CertificateRequestForKeyResponse")
//    public JAXBElement<GetPKCS10CertificateRequestForKeyResponse> createGetPKCS10CertificateRequestForKeyResponse(GetPKCS10CertificateRequestForKeyResponse value) {
//        return new JAXBElement<GetPKCS10CertificateRequestForKeyResponse>(_GetPKCS10CertificateRequestForKeyResponse_QNAME, GetPKCS10CertificateRequestForKeyResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetPKCS10CertificateRequestResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getPKCS10CertificateRequestResponse")
//    public JAXBElement<GetPKCS10CertificateRequestResponse> createGetPKCS10CertificateRequestResponse(GetPKCS10CertificateRequestResponse value) {
//        return new JAXBElement<GetPKCS10CertificateRequestResponse>(_GetPKCS10CertificateRequestResponse_QNAME, GetPKCS10CertificateRequestResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetSignerCertificate }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetSignerCertificate }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getSignerCertificate")
//    public JAXBElement<GetSignerCertificate> createGetSignerCertificate(GetSignerCertificate value) {
//        return new JAXBElement<GetSignerCertificate>(_GetSignerCertificate_QNAME, GetSignerCertificate.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetSignerCertificateChain }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetSignerCertificateChain }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getSignerCertificateChain")
//    public JAXBElement<GetSignerCertificateChain> createGetSignerCertificateChain(GetSignerCertificateChain value) {
//        return new JAXBElement<GetSignerCertificateChain>(_GetSignerCertificateChain_QNAME, GetSignerCertificateChain.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetSignerCertificateChainResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetSignerCertificateChainResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getSignerCertificateChainResponse")
//    public JAXBElement<GetSignerCertificateChainResponse> createGetSignerCertificateChainResponse(GetSignerCertificateChainResponse value) {
//        return new JAXBElement<GetSignerCertificateChainResponse>(_GetSignerCertificateChainResponse_QNAME, GetSignerCertificateChainResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetSignerCertificateResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetSignerCertificateResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getSignerCertificateResponse")
//    public JAXBElement<GetSignerCertificateResponse> createGetSignerCertificateResponse(GetSignerCertificateResponse value) {
//        return new JAXBElement<GetSignerCertificateResponse>(_GetSignerCertificateResponse_QNAME, GetSignerCertificateResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetSigningValidityNotAfter }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetSigningValidityNotAfter }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getSigningValidityNotAfter")
//    public JAXBElement<GetSigningValidityNotAfter> createGetSigningValidityNotAfter(GetSigningValidityNotAfter value) {
//        return new JAXBElement<GetSigningValidityNotAfter>(_GetSigningValidityNotAfter_QNAME, GetSigningValidityNotAfter.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetSigningValidityNotAfterResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetSigningValidityNotAfterResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getSigningValidityNotAfterResponse")
//    public JAXBElement<GetSigningValidityNotAfterResponse> createGetSigningValidityNotAfterResponse(GetSigningValidityNotAfterResponse value) {
//        return new JAXBElement<GetSigningValidityNotAfterResponse>(_GetSigningValidityNotAfterResponse_QNAME, GetSigningValidityNotAfterResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetSigningValidityNotBefore }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetSigningValidityNotBefore }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getSigningValidityNotBefore")
//    public JAXBElement<GetSigningValidityNotBefore> createGetSigningValidityNotBefore(GetSigningValidityNotBefore value) {
//        return new JAXBElement<GetSigningValidityNotBefore>(_GetSigningValidityNotBefore_QNAME, GetSigningValidityNotBefore.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetSigningValidityNotBeforeResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetSigningValidityNotBeforeResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getSigningValidityNotBeforeResponse")
//    public JAXBElement<GetSigningValidityNotBeforeResponse> createGetSigningValidityNotBeforeResponse(GetSigningValidityNotBeforeResponse value) {
//        return new JAXBElement<GetSigningValidityNotBeforeResponse>(_GetSigningValidityNotBeforeResponse_QNAME, GetSigningValidityNotBeforeResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetStatus }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetStatus }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getStatus")
//    public JAXBElement<GetStatus> createGetStatus(GetStatus value) {
//        return new JAXBElement<GetStatus>(_GetStatus_QNAME, GetStatus.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetStatusResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetStatusResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getStatusResponse")
//    public JAXBElement<GetStatusResponse> createGetStatusResponse(GetStatusResponse value) {
//        return new JAXBElement<GetStatusResponse>(_GetStatusResponse_QNAME, GetStatusResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetWorkerId }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetWorkerId }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getWorkerId")
//    public JAXBElement<GetWorkerId> createGetWorkerId(GetWorkerId value) {
//        return new JAXBElement<GetWorkerId>(_GetWorkerId_QNAME, GetWorkerId.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetWorkerIdResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetWorkerIdResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getWorkerIdResponse")
//    public JAXBElement<GetWorkerIdResponse> createGetWorkerIdResponse(GetWorkerIdResponse value) {
//        return new JAXBElement<GetWorkerIdResponse>(_GetWorkerIdResponse_QNAME, GetWorkerIdResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetWorkers }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetWorkers }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getWorkers")
//    public JAXBElement<GetWorkers> createGetWorkers(GetWorkers value) {
//        return new JAXBElement<GetWorkers>(_GetWorkers_QNAME, GetWorkers.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GetWorkersResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GetWorkersResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "getWorkersResponse")
//    public JAXBElement<GetWorkersResponse> createGetWorkersResponse(GetWorkersResponse value) {
//        return new JAXBElement<GetWorkersResponse>(_GetWorkersResponse_QNAME, GetWorkersResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GlobalReload }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GlobalReload }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "globalReload")
//    public JAXBElement<GlobalReload> createGlobalReload(GlobalReload value) {
//        return new JAXBElement<GlobalReload>(_GlobalReload_QNAME, GlobalReload.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GlobalReloadResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GlobalReloadResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "globalReloadResponse")
//    public JAXBElement<GlobalReloadResponse> createGlobalReloadResponse(GlobalReloadResponse value) {
//        return new JAXBElement<GlobalReloadResponse>(_GlobalReloadResponse_QNAME, GlobalReloadResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GlobalResync }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GlobalResync }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "globalResync")
//    public JAXBElement<GlobalResync> createGlobalResync(GlobalResync value) {
//        return new JAXBElement<GlobalResync>(_GlobalResync_QNAME, GlobalResync.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link GlobalResyncResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link GlobalResyncResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "globalResyncResponse")
//    public JAXBElement<GlobalResyncResponse> createGlobalResyncResponse(GlobalResyncResponse value) {
//        return new JAXBElement<GlobalResyncResponse>(_GlobalResyncResponse_QNAME, GlobalResyncResponse.class, null, value);
//    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link ImportCertificateChain }{@code >}
     *
     * @param value
     *     Java instance representing xml element's value.
     * @return
     *     the new instance of {@link JAXBElement }{@code <}{@link ImportCertificateChain }{@code >}
     */
    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "importCertificateChain")
    public JAXBElement<ImportCertificateChain> createImportCertificateChain(ImportCertificateChain value) {
        return new JAXBElement<ImportCertificateChain>(_ImportCertificateChain_QNAME, ImportCertificateChain.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link ImportCertificateChainResponse }{@code >}
     *
     * @param value
     *     Java instance representing xml element's value.
     * @return
     *     the new instance of {@link JAXBElement }{@code <}{@link ImportCertificateChainResponse }{@code >}
     */
    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "importCertificateChainResponse")
    public JAXBElement<ImportCertificateChainResponse> createImportCertificateChainResponse(ImportCertificateChainResponse value) {
        return new JAXBElement<ImportCertificateChainResponse>(_ImportCertificateChainResponse_QNAME, ImportCertificateChainResponse.class, null, value);
    }

//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link Process }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link Process }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "process")
//    public JAXBElement<Process> createProcess(Process value) {
//        return new JAXBElement<Process>(_Process_QNAME, Process.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link ProcessResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link ProcessResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "processResponse")
//    public JAXBElement<ProcessResponse> createProcessResponse(ProcessResponse value) {
//        return new JAXBElement<ProcessResponse>(_ProcessResponse_QNAME, ProcessResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link QueryArchive }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link QueryArchive }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "queryArchive")
//    public JAXBElement<QueryArchive> createQueryArchive(QueryArchive value) {
//        return new JAXBElement<QueryArchive>(_QueryArchive_QNAME, QueryArchive.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link QueryArchiveResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link QueryArchiveResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "queryArchiveResponse")
//    public JAXBElement<QueryArchiveResponse> createQueryArchiveResponse(QueryArchiveResponse value) {
//        return new JAXBElement<QueryArchiveResponse>(_QueryArchiveResponse_QNAME, QueryArchiveResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link QueryArchiveWithIds }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link QueryArchiveWithIds }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "queryArchiveWithIds")
//    public JAXBElement<QueryArchiveWithIds> createQueryArchiveWithIds(QueryArchiveWithIds value) {
//        return new JAXBElement<QueryArchiveWithIds>(_QueryArchiveWithIds_QNAME, QueryArchiveWithIds.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link QueryArchiveWithIdsResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link QueryArchiveWithIdsResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "queryArchiveWithIdsResponse")
//    public JAXBElement<QueryArchiveWithIdsResponse> createQueryArchiveWithIdsResponse(QueryArchiveWithIdsResponse value) {
//        return new JAXBElement<QueryArchiveWithIdsResponse>(_QueryArchiveWithIdsResponse_QNAME, QueryArchiveWithIdsResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link QueryAuditLog }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link QueryAuditLog }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "queryAuditLog")
//    public JAXBElement<QueryAuditLog> createQueryAuditLog(QueryAuditLog value) {
//        return new JAXBElement<QueryAuditLog>(_QueryAuditLog_QNAME, QueryAuditLog.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link QueryAuditLogResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link QueryAuditLogResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "queryAuditLogResponse")
//    public JAXBElement<QueryAuditLogResponse> createQueryAuditLogResponse(QueryAuditLogResponse value) {
//        return new JAXBElement<QueryAuditLogResponse>(_QueryAuditLogResponse_QNAME, QueryAuditLogResponse.class, null, value);
//    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link QueryTokenEntries }{@code >}
     *
     * @param value
     *     Java instance representing xml element's value.
     * @return
     *     the new instance of {@link JAXBElement }{@code <}{@link QueryTokenEntries }{@code >}
     */
    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "queryTokenEntries")
    public JAXBElement<QueryTokenEntries> createQueryTokenEntries(QueryTokenEntries value) {
        return new JAXBElement<>(_QueryTokenEntries_QNAME, QueryTokenEntries.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link QueryTokenEntriesResponse }{@code >}
     *
     * @param value
     *     Java instance representing xml element's value.
     * @return
     *     the new instance of {@link JAXBElement }{@code <}{@link QueryTokenEntriesResponse }{@code >}
     */
    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "queryTokenEntriesResponse")
    public JAXBElement<QueryTokenEntriesResponse> createQueryTokenEntriesResponse(QueryTokenEntriesResponse value) {
        return new JAXBElement<>(_QueryTokenEntriesResponse_QNAME, QueryTokenEntriesResponse.class, null, value);
    }

//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link ReloadConfiguration }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link ReloadConfiguration }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "reloadConfiguration")
//    public JAXBElement<ReloadConfiguration> createReloadConfiguration(ReloadConfiguration value) {
//        return new JAXBElement<ReloadConfiguration>(_ReloadConfiguration_QNAME, ReloadConfiguration.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link ReloadConfigurationResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link ReloadConfigurationResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "reloadConfigurationResponse")
//    public JAXBElement<ReloadConfigurationResponse> createReloadConfigurationResponse(ReloadConfigurationResponse value) {
//        return new JAXBElement<ReloadConfigurationResponse>(_ReloadConfigurationResponse_QNAME, ReloadConfigurationResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link RemoveAuthorizedClient }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link RemoveAuthorizedClient }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "removeAuthorizedClient")
//    public JAXBElement<RemoveAuthorizedClient> createRemoveAuthorizedClient(RemoveAuthorizedClient value) {
//        return new JAXBElement<RemoveAuthorizedClient>(_RemoveAuthorizedClient_QNAME, RemoveAuthorizedClient.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link RemoveAuthorizedClientResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link RemoveAuthorizedClientResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "removeAuthorizedClientResponse")
//    public JAXBElement<RemoveAuthorizedClientResponse> createRemoveAuthorizedClientResponse(RemoveAuthorizedClientResponse value) {
//        return new JAXBElement<RemoveAuthorizedClientResponse>(_RemoveAuthorizedClientResponse_QNAME, RemoveAuthorizedClientResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link RemoveGlobalProperty }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link RemoveGlobalProperty }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "removeGlobalProperty")
//    public JAXBElement<RemoveGlobalProperty> createRemoveGlobalProperty(RemoveGlobalProperty value) {
//        return new JAXBElement<RemoveGlobalProperty>(_RemoveGlobalProperty_QNAME, RemoveGlobalProperty.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link RemoveGlobalPropertyResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link RemoveGlobalPropertyResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "removeGlobalPropertyResponse")
//    public JAXBElement<RemoveGlobalPropertyResponse> createRemoveGlobalPropertyResponse(RemoveGlobalPropertyResponse value) {
//        return new JAXBElement<RemoveGlobalPropertyResponse>(_RemoveGlobalPropertyResponse_QNAME, RemoveGlobalPropertyResponse.class, null, value);
//    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link RemoveKey }{@code >}
     *
     * @param value
     *     Java instance representing xml element's value.
     * @return
     *     the new instance of {@link JAXBElement }{@code <}{@link RemoveKey }{@code >}
     */
    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "removeKey")
    public JAXBElement<RemoveKey> createRemoveKey(RemoveKey value) {
        return new JAXBElement<RemoveKey>(_RemoveKey_QNAME, RemoveKey.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link RemoveKeyResponse }{@code >}
     *
     * @param value
     *     Java instance representing xml element's value.
     * @return
     *     the new instance of {@link JAXBElement }{@code <}{@link RemoveKeyResponse }{@code >}
     */
    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "removeKeyResponse")
    public JAXBElement<RemoveKeyResponse> createRemoveKeyResponse(RemoveKeyResponse value) {
        return new JAXBElement<RemoveKeyResponse>(_RemoveKeyResponse_QNAME, RemoveKeyResponse.class, null, value);
    }

//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link RemoveWorkerProperty }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link RemoveWorkerProperty }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "removeWorkerProperty")
//    public JAXBElement<RemoveWorkerProperty> createRemoveWorkerProperty(RemoveWorkerProperty value) {
//        return new JAXBElement<RemoveWorkerProperty>(_RemoveWorkerProperty_QNAME, RemoveWorkerProperty.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link RemoveWorkerPropertyResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link RemoveWorkerPropertyResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "removeWorkerPropertyResponse")
//    public JAXBElement<RemoveWorkerPropertyResponse> createRemoveWorkerPropertyResponse(RemoveWorkerPropertyResponse value) {
//        return new JAXBElement<RemoveWorkerPropertyResponse>(_RemoveWorkerPropertyResponse_QNAME, RemoveWorkerPropertyResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link SetGlobalProperty }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link SetGlobalProperty }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "setGlobalProperty")
//    public JAXBElement<SetGlobalProperty> createSetGlobalProperty(SetGlobalProperty value) {
//        return new JAXBElement<SetGlobalProperty>(_SetGlobalProperty_QNAME, SetGlobalProperty.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link SetGlobalPropertyResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link SetGlobalPropertyResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "setGlobalPropertyResponse")
//    public JAXBElement<SetGlobalPropertyResponse> createSetGlobalPropertyResponse(SetGlobalPropertyResponse value) {
//        return new JAXBElement<SetGlobalPropertyResponse>(_SetGlobalPropertyResponse_QNAME, SetGlobalPropertyResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link SetWorkerProperty }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link SetWorkerProperty }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "setWorkerProperty")
//    public JAXBElement<SetWorkerProperty> createSetWorkerProperty(SetWorkerProperty value) {
//        return new JAXBElement<SetWorkerProperty>(_SetWorkerProperty_QNAME, SetWorkerProperty.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link SetWorkerPropertyResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link SetWorkerPropertyResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "setWorkerPropertyResponse")
//    public JAXBElement<SetWorkerPropertyResponse> createSetWorkerPropertyResponse(SetWorkerPropertyResponse value) {
//        return new JAXBElement<SetWorkerPropertyResponse>(_SetWorkerPropertyResponse_QNAME, SetWorkerPropertyResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link TestKey }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link TestKey }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "testKey")
//    public JAXBElement<TestKey> createTestKey(TestKey value) {
//        return new JAXBElement<TestKey>(_TestKey_QNAME, TestKey.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link TestKeyResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link TestKeyResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "testKeyResponse")
//    public JAXBElement<TestKeyResponse> createTestKeyResponse(TestKeyResponse value) {
//        return new JAXBElement<TestKeyResponse>(_TestKeyResponse_QNAME, TestKeyResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link UploadSignerCertificate }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link UploadSignerCertificate }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "uploadSignerCertificate")
//    public JAXBElement<UploadSignerCertificate> createUploadSignerCertificate(UploadSignerCertificate value) {
//        return new JAXBElement<UploadSignerCertificate>(_UploadSignerCertificate_QNAME, UploadSignerCertificate.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link UploadSignerCertificateChain }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link UploadSignerCertificateChain }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "uploadSignerCertificateChain")
//    public JAXBElement<UploadSignerCertificateChain> createUploadSignerCertificateChain(UploadSignerCertificateChain value) {
//        return new JAXBElement<UploadSignerCertificateChain>(_UploadSignerCertificateChain_QNAME, UploadSignerCertificateChain.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link UploadSignerCertificateChainResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link UploadSignerCertificateChainResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "uploadSignerCertificateChainResponse")
//    public JAXBElement<UploadSignerCertificateChainResponse> createUploadSignerCertificateChainResponse(UploadSignerCertificateChainResponse value) {
//        return new JAXBElement<UploadSignerCertificateChainResponse>(_UploadSignerCertificateChainResponse_QNAME, UploadSignerCertificateChainResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link UploadSignerCertificateResponse }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link UploadSignerCertificateResponse }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "uploadSignerCertificateResponse")
//    public JAXBElement<UploadSignerCertificateResponse> createUploadSignerCertificateResponse(UploadSignerCertificateResponse value) {
//        return new JAXBElement<UploadSignerCertificateResponse>(_UploadSignerCertificateResponse_QNAME, UploadSignerCertificateResponse.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link InvalidWorkerIdException }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link InvalidWorkerIdException }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "InvalidWorkerIdException")
//    public JAXBElement<InvalidWorkerIdException> createInvalidWorkerIdException(InvalidWorkerIdException value) {
//        return new JAXBElement<InvalidWorkerIdException>(_InvalidWorkerIdException_QNAME, InvalidWorkerIdException.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link AdminNotAuthorizedException }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link AdminNotAuthorizedException }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "AdminNotAuthorizedException")
//    public JAXBElement<AdminNotAuthorizedException> createAdminNotAuthorizedException(AdminNotAuthorizedException value) {
//        return new JAXBElement<AdminNotAuthorizedException>(_AdminNotAuthorizedException_QNAME, AdminNotAuthorizedException.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link SignServerException }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link SignServerException }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "SignServerException")
//    public JAXBElement<SignServerException> createSignServerException(SignServerException value) {
//        return new JAXBElement<SignServerException>(_SignServerException_QNAME, SignServerException.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link CryptoTokenOfflineException }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link CryptoTokenOfflineException }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "CryptoTokenOfflineException")
//    public JAXBElement<CryptoTokenOfflineException> createCryptoTokenOfflineException(CryptoTokenOfflineException value) {
//        return new JAXBElement<CryptoTokenOfflineException>(_CryptoTokenOfflineException_QNAME, CryptoTokenOfflineException.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link OperationUnsupportedException }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link OperationUnsupportedException }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "OperationUnsupportedException")
//    public JAXBElement<OperationUnsupportedException> createOperationUnsupportedException(OperationUnsupportedException value) {
//        return new JAXBElement<OperationUnsupportedException>(_OperationUnsupportedException_QNAME, OperationUnsupportedException.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link CertificateException }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link CertificateException }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "CertificateException")
//    public JAXBElement<CertificateException> createCertificateException(CertificateException value) {
//        return new JAXBElement<CertificateException>(_CertificateException_QNAME, CertificateException.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link KeyStoreException }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link KeyStoreException }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "KeyStoreException")
//    public JAXBElement<KeyStoreException> createKeyStoreException(KeyStoreException value) {
//        return new JAXBElement<KeyStoreException>(_KeyStoreException_QNAME, KeyStoreException.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link AuthorizationDeniedException }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link AuthorizationDeniedException }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "AuthorizationDeniedException")
//    public JAXBElement<AuthorizationDeniedException> createAuthorizationDeniedException(AuthorizationDeniedException value) {
//        return new JAXBElement<AuthorizationDeniedException>(_AuthorizationDeniedException_QNAME, AuthorizationDeniedException.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link QueryException }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link QueryException }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "QueryException")
//    public JAXBElement<QueryException> createQueryException(QueryException value) {
//        return new JAXBElement<QueryException>(_QueryException_QNAME, QueryException.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link IllegalRequestException }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link IllegalRequestException }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "IllegalRequestException")
//    public JAXBElement<IllegalRequestException> createIllegalRequestException(IllegalRequestException value) {
//        return new JAXBElement<IllegalRequestException>(_IllegalRequestException_QNAME, IllegalRequestException.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link CryptoTokenAuthenticationFailureException }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link CryptoTokenAuthenticationFailureException }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "CryptoTokenAuthenticationFailureException")
//    public JAXBElement<CryptoTokenAuthenticationFailureException> createCryptoTokenAuthenticationFailureException(CryptoTokenAuthenticationFailureException value) {
//        return new JAXBElement<CryptoTokenAuthenticationFailureException>(_CryptoTokenAuthenticationFailureException_QNAME, CryptoTokenAuthenticationFailureException.class, null, value);
//    }
//
//    /**
//     * Create an instance of {@link JAXBElement }{@code <}{@link ResyncException }{@code >}
//     *
//     * @param value
//     *     Java instance representing xml element's value.
//     * @return
//     *     the new instance of {@link JAXBElement }{@code <}{@link ResyncException }{@code >}
//     */
//    @XmlElementDecl(namespace = "http://adminws.signserver.org/", name = "ResyncException")
//    public JAXBElement<ResyncException> createResyncException(ResyncException value) {
//        return new JAXBElement<ResyncException>(_ResyncException_QNAME, ResyncException.class, null, value);
//    }

}
