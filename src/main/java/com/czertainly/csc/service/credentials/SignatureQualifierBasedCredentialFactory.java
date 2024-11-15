package com.czertainly.csc.service.credentials;

import com.czertainly.csc.api.auth.CscAuthenticationToken;
import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.clients.ejbca.EjbcaClient;
import com.czertainly.csc.clients.signserver.SignserverClient;
import com.czertainly.csc.common.result.Error;
import com.czertainly.csc.common.result.Result;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.crypto.PasswordGenerator;
import com.czertainly.csc.model.UserInfo;
import com.czertainly.csc.model.csc.SignatureQualifierBasedCredentialMetadata;
import com.czertainly.csc.model.ejbca.EndEntity;
import com.czertainly.csc.model.signserver.CryptoTokenKey;
import com.czertainly.csc.providers.KeyValueSource;
import com.czertainly.csc.signing.UserInfoProvider;
import com.czertainly.csc.signing.configuration.profiles.CredentialProfileRepository;
import com.czertainly.csc.signing.configuration.profiles.signaturequalifierprofile.SignatureQualifierProfile;
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

    public SignatureQualifierBasedCredentialFactory(UserInfoProvider userInfoProvider,
                                                    PasswordGenerator passwordGenerator,
                                                    CredentialProfileRepository credentialProfileRepository,
                                                    SignserverClient signserverClient, EjbcaClient ejbcaClient
    ) {
        this.userInfoProvider = userInfoProvider;
        this.passwordGenerator = passwordGenerator;
        this.credentialProfileRepository = credentialProfileRepository;
        this.signserverClient = signserverClient;
        this.ejbcaClient = ejbcaClient;
    }

    public Result<SignatureQualifierBasedCredentialMetadata, TextError> createCredential(
            CryptoTokenKey key,
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

        return Result.success(new SignatureQualifierBasedCredentialMetadata(
                userId, key, endEntity.username(), signatureQualifierProfile.getName(),
                signatureQualifierProfile.getMultisgn()
        ));
    }

    private Result<Void, TextError> generateCertificateForSigningKey(
            CryptoTokenKey key, String dn, EndEntity endEntity, SignatureQualifierProfile signatureQualifierProfile
    ) {
        return signserverClient.generateCSR(
                                       key.cryptoToken(), key.keyAlias(), dn,
                                       signatureQualifierProfile.getCsrSignatureAlgorithm()
                               )
                               .flatMap(csr -> ejbcaClient.signCertificateRequest(
                                       endEntity,
                                       signatureQualifierProfile,
                                       csr
                               ))
                               .flatMap(certificateChain -> signserverClient.importCertificateChain(
                                       key.cryptoToken(), key.keyAlias(), List.of(certificateChain)
                               ));
    }
}
