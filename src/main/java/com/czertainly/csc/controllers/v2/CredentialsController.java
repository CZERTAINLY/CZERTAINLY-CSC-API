package com.czertainly.csc.controllers.v2;

import com.czertainly.csc.api.credentials.*;
import com.czertainly.csc.api.mappers.credentials.CredentialInfoRequestMapper;
import com.czertainly.csc.components.DateConverter;
import com.czertainly.csc.controllers.exceptions.BadRequestException;
import com.czertainly.csc.controllers.exceptions.ServerErrorException;
import com.czertainly.csc.model.csc.Credential;
import com.czertainly.csc.model.csc.requests.CredentialInfoRequest;
import com.czertainly.csc.service.CredentialsService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("csc/v2/credentials")
public class CredentialsController {

    private final CredentialsService credentialsService;
    private final DateConverter dateConverter;

    private final CredentialInfoRequestMapper credentialInfoRequestMapper;

    public CredentialsController(CredentialsService credentialsService, DateConverter dateConverter,
                                 CredentialInfoRequestMapper credentialInfoRequestMapper
    ) {
        this.credentialsService = credentialsService;
        this.dateConverter = dateConverter;
        this.credentialInfoRequestMapper = credentialInfoRequestMapper;
    }

    @RequestMapping(path = "list", method = RequestMethod.POST, produces = "application/json")
    @PreAuthorize("hasAuthority('SCOPE_createCredential')")
    public CredentialsListDto listCredentials() {

        return new CredentialsListDto(
                List.of("credential1"),
                List.of(
                        new CredentialDto(
                                "credential1",
                                "enabled",
                                "ue_eidas",
                                new KeyDto(
                                        "enabled",
                                        List.of("1.2.840.113549.1.1.1"),
                                        2048,
                                        null
                                ),
                                new CertificateDto(
                                        "valid",
                                        List.of("asfikjhasfkj"),
                                        "FIRST CERT AUTHORITY",
                                        "123",
                                        "My Signing Certificate",
                                        "2022-01-01T00:00:00Z",
                                        "2023-01-01T00:00:00Z"
                                ),
                                3
                        )
                ),
                true
        );
    }

    @RequestMapping(path = "info", method = RequestMethod.POST, produces = "application/json")
    public CredentialDto credentialInfo(@RequestBody CredentialInfoDto credentialInfoDto) {
        return credentialInfoRequestMapper
                .map(credentialInfoDto, null)
                .with(
                        (CredentialInfoRequest request) -> {
                            try {
                                Credential credential = credentialsService.getCredential(request);
                                return CredentialDto.fromModel(credential, dateConverter);
                            } catch (Exception e) {
                                throw new ServerErrorException("Server error", e.getMessage());
                            }
                        },
                        (error) -> {
                            throw new BadRequestException(error.error(), error.description());
                        }
                );
    }
}
