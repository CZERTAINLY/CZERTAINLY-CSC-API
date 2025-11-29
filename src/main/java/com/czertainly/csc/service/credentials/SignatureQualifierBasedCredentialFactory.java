package com.czertainly.csc.service.credentials;

import com.czertainly.csc.api.auth.CscAuthenticationToken;
import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.clients.ejbca.EjbcaClient;
import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.crypto.CertificateParser;
import com.czertainly.csc.crypto.PasswordGenerator;
import com.czertainly.csc.model.CertificateRevocationReason;
import com.czertainly.csc.model.UserInfo;
import com.czertainly.csc.model.csc.SignatureQualifierBasedCredentialMetadata;
import com.czertainly.csc.model.ejbca.EndEntity;
import com.czertainly.csc.providers.KeyValueSource;
import com.czertainly.csc.service.keys.SigningKey;
import com.czertainly.csc.signing.UserInfoProvider;
import com.czertainly.csc.signing.configuration.profiles.CredentialProfileRepository;
import com.czertainly.csc.signing.configuration.profiles.signaturequalifierprofile.SignatureQualifierProfile;
import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class SignatureQualifierBasedCredentialFactory {

    public static final Logger logger = LoggerFactory.getLogger(SignatureQualifierBasedCredentialFactory.class);

    private final UserInfoProvider userInfoProvider;
    private final PasswordGenerator passwordGenerator;
    private final CredentialProfileRepository credentialProfileRepository;
    private final SignserverClient signserverClient;
    private final EjbcaClient ejbcaClient;
    private final CertificateParser certificateParser;

    public SignatureQualifierBasedCredentialFactory(UserInfoProvider userInfoProvider,
                                                    PasswordGenerator passwordGenerator,
                                                    CredentialProfileRepository credentialProfileRepository,
                                                    SignserverClient signserverClient, EjbcaClient ejbcaClient,
                                                    CertificateParser certificateParser
    ) {
        this.userInfoProvider = userInfoProvider;
        this.passwordGenerator = passwordGenerator;
        this.credentialProfileRepository = credentialProfileRepository;
        this.signserverClient = signserverClient;
        this.ejbcaClient = ejbcaClient;
        this.certificateParser = certificateParser;
    }

    public <K extends SigningKey> Result<SignatureQualifierBasedCredentialMetadata<K>, TextError> createCredential(
            K key,
            String signatureQualifier,
            String userId,
            SignatureActivationData sad,
            CscAuthenticationToken cscAuthenticationToken
    ) {
        String accessToken = cscAuthenticationToken.getToken().getTokenValue();
        var getUserInfoResult = userInfoProvider.getUserInfo(accessToken);
        if (getUserInfoResult instanceof Error(var err)) {
            return Result.error(err);
        }
        UserInfo userInfo = getUserInfoResult.unwrap();

        KeyValueSource keyValueSource = new KeyValueSource(
                key.keyAlias(), userInfo, cscAuthenticationToken, sad
        );

        var getProfileResult = credentialProfileRepository
                .getSignatureQualifierProfile(signatureQualifier)
                .consume((signatureQualifierProfile) -> {
                    logger.info("Will use signature qualifier profile {} to create a credential.",
                                signatureQualifierProfile.getName()
                    );
                    logger.debug(signatureQualifierProfile.toString());
                })
                .mapError(err -> err.extend("Failed to load signature qualifier profile."));
        if (getProfileResult instanceof Error(var err)) return Result.error(err);
        SignatureQualifierProfile signatureQualifierProfile = getProfileResult.unwrap();

        var getDnResult = signatureQualifierProfile.getDistinguishedNameProvider()
                                                   .getDistinguishedName(keyValueSource.getSupplier());
        if (getDnResult instanceof Error(var err)) {
            return Result.error(err);
        }
        var dn = getDnResult.unwrap();

        var getSanResult = signatureQualifierProfile.getSubjectAlternativeNameProvider()
                                                    .getSan(keyValueSource.getSupplier());
        if (getSanResult instanceof Error(var err)) {
            return Result.error(err);
        }
        var san = getSanResult.unwrap();

        var getUsernameResult = signatureQualifierProfile.getUsernameProvider()
                                                         .getUsername(keyValueSource.getSupplier());
        if (getUsernameResult instanceof Error(var err)) {
            return Result.error(err);
        }
        var username = getUsernameResult.unwrap();

        var getPasswordResult = passwordGenerator.generate();
        if (getPasswordResult instanceof Error(var err)) {
            return Result.error(err);
        }
        var password = getPasswordResult.unwrap();

        EndEntity endEntity = new EndEntity(username, password, dn, san);
        var createEndEndtityResult = ejbcaClient.createEndEntity(endEntity, signatureQualifierProfile);
        if (createEndEndtityResult instanceof Error(var err)) {
            return Result.error(err);
        }

        var certifyKeyResult = generateCertificateForSigningKey(key, dn, endEntity, signatureQualifierProfile);
        if (certifyKeyResult instanceof Error(var err)) {
            return Result.error(err);
        }
        X509CertificateHolder certificate = certifyKeyResult.unwrap();

        return Result.success(new SignatureQualifierBasedCredentialMetadata<>(
                userId, key, endEntity.username(), certificate, signatureQualifierProfile.getName(),
                signatureQualifierProfile.getMultisign()
        ));
    }

    public <K extends SigningKey> void rollbackCredentialCreation(
            SignatureQualifierBasedCredentialMetadata<K> credentialMetadata
    ) {
        revokeCertificate(credentialMetadata.certificate());
    }

    private Result<X509CertificateHolder, TextError> generateCertificateForSigningKey(
            SigningKey key, String dn, EndEntity endEntity, SignatureQualifierProfile signatureQualifierProfile
    ) {
        var csrSignResult = signserverClient.generateCSR(
                                                    key.cryptoToken(), key.keyAlias(), dn,
                                                    signatureQualifierProfile.getCsrSignatureAlgorithm()
                                            )
                                            .flatMap(csr -> ejbcaClient.signCertificateRequest(
                                                    endEntity,
                                                    signatureQualifierProfile,
                                                    csr
                                            ));

        if (csrSignResult instanceof Error(var err)) {
            return Result.error(err);
        }
        byte[] certificateChain = csrSignResult.unwrap();

        var parseCertificateResult = certificateParser.getEndCertificateFromPkcs7Chain(certificateChain)
                                                      .mapError(e -> e.extend(
                                                              "End certificate couldn't be extracted from PKCS7 chain."));
        if (parseCertificateResult instanceof Error(var err)) {
            return Result.error(err);
        }
        X509CertificateHolder certificate = parseCertificateResult.unwrap();

        return signserverClient.importCertificateChain(key.cryptoToken(), key.keyAlias(), List.of(certificateChain))
                               .ifError(() -> revokeCertificate(certificate))
                               .map((v) -> certificate);
    }

    private void revokeCertificate(X509CertificateHolder certificate) {
        logger.info("Revoking certificate '{}' due to an error during session credential creation.",
                    certificate.getSerialNumber()
        );
        ejbcaClient.revokeCertificate(
                           certificate.getSerialNumber().toString(16), certificate.getIssuer().toString(),
                           CertificateRevocationReason.UNSPECIFIED
                   )
                   .consumeError(e -> logger.error(
                           e.extend(
                                   "Failed to revoke certificate '%s'. The certificate should be revoked manually.",
                                   certificate.getSerialNumber()
                           ).getErrorText()
                   ));

    }
}
