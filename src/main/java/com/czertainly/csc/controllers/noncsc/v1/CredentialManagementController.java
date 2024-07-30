package com.czertainly.csc.controllers.noncsc.v1;

import com.czertainly.csc.api.management.CreateCredentialDto;
import com.czertainly.csc.api.management.RekeyCredentialDto;
import com.czertainly.csc.api.management.SelectCredentialDto;
import com.czertainly.csc.api.mappers.credentials.CredentialUUIDMapper;
import com.czertainly.csc.api.mappers.credentials.RekeyCertificateRequestMapper;
import com.czertainly.csc.controllers.exceptions.BadRequestException;
import com.czertainly.csc.service.CredentialsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("management/v1/credentials")
public class CredentialManagementController {

    private final CredentialsService credentialsService;
    private final CredentialUUIDMapper credentialUUIDMapper;
    private final RekeyCertificateRequestMapper rekeyCertificateRequestMapper;

    public CredentialManagementController(@Autowired CredentialsService credentialsService,
                                          CredentialUUIDMapper credentialUUIDMapper,
                                          RekeyCertificateRequestMapper rekeyCertificateRequestMapper
    ) {
        this.credentialsService = credentialsService;
        this.credentialUUIDMapper = credentialUUIDMapper;
        this.rekeyCertificateRequestMapper = rekeyCertificateRequestMapper;
    }

    @RequestMapping(path = "/create", method = RequestMethod.POST, produces = "application/json")
    @PreAuthorize("hasAuthority('SCOPE_manageCredentials')")
    public String createCredential(@RequestBody CreateCredentialDto createCredentialDto) {
        return this.credentialsService.createCredential(createCredentialDto.toModel()).toString();
    }

    @RequestMapping(path = "/remove", method = RequestMethod.POST, produces = "application/json")
    @PreAuthorize("hasAuthority('SCOPE_manageCredentials')")
    public void deleteCredential(@RequestBody SelectCredentialDto selectCredentialDto) {
        credentialUUIDMapper.map(selectCredentialDto, null).doWith(this.credentialsService::deleteCredential, error -> {
            throw new BadRequestException(error.error(), error.description());
        });
    }

    @RequestMapping(path = "/disable", method = RequestMethod.POST, produces = "application/json")
    @PreAuthorize("hasAuthority('SCOPE_manageCredentials')")
    public void disableCredential(@RequestBody SelectCredentialDto selectCredentialDto) {
        credentialUUIDMapper.map(selectCredentialDto, null)
                            .doWith(this.credentialsService::disableCredential, error -> {
                                throw new BadRequestException(error.error(), error.description());
                            });

    }

    @RequestMapping(path = "/enable", method = RequestMethod.POST, produces = "application/json")
    @PreAuthorize("hasAuthority('SCOPE_manageCredentials')")
    public void enableCredential(@RequestBody SelectCredentialDto selectCredentialDto) {
        credentialUUIDMapper.map(selectCredentialDto, null).doWith(this.credentialsService::enableCredential, error -> {
            throw new BadRequestException(error.error(), error.description());
        });

    }

    @RequestMapping(path = "/rekey", method = RequestMethod.POST, produces = "application/json")
    @PreAuthorize("hasAuthority('SCOPE_manageCredentials')")
    public void revokeCredential(@RequestBody RekeyCredentialDto rekeyCredentialDto) {
        rekeyCertificateRequestMapper.map(rekeyCredentialDto, null).doWith(this.credentialsService::rekey, error -> {
            throw new BadRequestException(error.error(), error.description());
        });
    }
}
