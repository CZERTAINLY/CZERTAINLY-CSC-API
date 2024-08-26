package com.czertainly.csc.controllers.noncsc.v1;

import com.czertainly.csc.api.common.ErrorDto;
import com.czertainly.csc.api.management.CreateCredentialDto;
import com.czertainly.csc.api.management.CredentialIdDto;
import com.czertainly.csc.api.management.RekeyCredentialDto;
import com.czertainly.csc.api.management.SelectCredentialDto;
import com.czertainly.csc.api.mappers.credentials.CreateCredentialRequestMapper;
import com.czertainly.csc.api.mappers.credentials.CredentialUUIDMapper;
import com.czertainly.csc.api.mappers.credentials.RekeyCertificateRequestMapper;
import com.czertainly.csc.controllers.exceptions.BadRequestException;
import com.czertainly.csc.service.CredentialsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("management/v1/credentials")
@PreAuthorize("hasAuthority('SCOPE_manageCredentials')")
@Tag(name = "Credentials Management", description = "An API for managing credentials. This API is not part of the CSC API specification.")
@ApiResponses(
        value = {
                @ApiResponse(
                        responseCode = "400",
                        description = "Bad Request",
                        content = @Content(schema = @Schema(implementation = ErrorDto.class))
                ),
                @ApiResponse(
                        responseCode = "401",
                        description = "Unauthorized",
                        content = @Content
                ),
                @ApiResponse(
                        responseCode = "500",
                        description = "Internal Server Error",
                        content = @Content
                )

        })
public class CredentialManagementController {

    private final CredentialsService credentialsService;
    private final CreateCredentialRequestMapper createCredentialRequestMapper;
    private final CredentialUUIDMapper credentialUUIDMapper;
    private final RekeyCertificateRequestMapper rekeyCertificateRequestMapper;

    public CredentialManagementController(@Autowired CredentialsService credentialsService,
                                          CreateCredentialRequestMapper createCredentialRequestMapper,
                                          CredentialUUIDMapper credentialUUIDMapper,
                                          RekeyCertificateRequestMapper rekeyCertificateRequestMapper
    ) {
        this.credentialsService = credentialsService;
        this.createCredentialRequestMapper = createCredentialRequestMapper;
        this.credentialUUIDMapper = credentialUUIDMapper;
        this.rekeyCertificateRequestMapper = rekeyCertificateRequestMapper;
    }

    @RequestMapping(path = "/create", method = RequestMethod.POST, produces = "application/json")
    @Operation(summary = "Create Credential",
            description = "Creates a new credential for a user."
    )
    @ApiResponses(
            value = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(schema = @Schema(implementation = CredentialIdDto.class))
                    )
            }
    )
    public CredentialIdDto createCredential(@RequestBody CreateCredentialDto createCredentialDto) {
        return createCredentialRequestMapper
                .map(createCredentialDto, null)
                .with(request -> {
                          UUID credentialId = this.credentialsService.createCredential(request);
                          return new CredentialIdDto(credentialId.toString());
                      },
                      error -> {
                          throw new BadRequestException(error.error(), error.description());
                      }
                );
    }

    @RequestMapping(path = "/remove", method = RequestMethod.POST, produces = "application/json")
    @Operation(summary = "Remove Credential",
            description = "Deletes the credential and all associated resources."
    )
    @ApiResponses(
            value = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation"
                    )
            }
    )
    public void deleteCredential(@RequestBody SelectCredentialDto selectCredentialDto) {
        credentialUUIDMapper.map(selectCredentialDto, null).doWith(this.credentialsService::deleteCredential, error -> {
            throw new BadRequestException(error.error(), error.description());
        });
    }

    @RequestMapping(path = "/disable", method = RequestMethod.POST, produces = "application/json")
    @Operation(summary = "Disable Credential",
            description = "Disables the the credential so it can no longer be used for signing."
    )
    @ApiResponses(
            value = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation"
                    )
            }
    )
    public void disableCredential(@RequestBody SelectCredentialDto selectCredentialDto) {
        credentialUUIDMapper.map(selectCredentialDto, null)
                            .doWith(this.credentialsService::disableCredential, error -> {
                                throw new BadRequestException(error.error(), error.description());
                            });

    }

    @RequestMapping(path = "/enable", method = RequestMethod.POST, produces = "application/json")
    @Operation(summary = "Enable Credential",
            description = "Enables the the credential so it can be used for signing."
    )
    @ApiResponses(
            value = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation"
                    )
            }
    )
    public void enableCredential(@RequestBody SelectCredentialDto selectCredentialDto) {
        credentialUUIDMapper.map(selectCredentialDto, null).doWith(this.credentialsService::enableCredential, error -> {
            throw new BadRequestException(error.error(), error.description());
        });

    }

    @RequestMapping(path = "/rekey", method = RequestMethod.POST, produces = "application/json")
    @Operation(summary = "Rekey Credential",
            description = "Generates a new signing key and certificate for the credential."
    )
    @ApiResponses(
            value = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation"
                    )
            }
    )
    public void rekeyCredential(@RequestBody RekeyCredentialDto rekeyCredentialDto) {
        rekeyCertificateRequestMapper.map(rekeyCredentialDto, null).doWith(this.credentialsService::rekey, error -> {
            throw new BadRequestException(error.error(), error.description());
        });
    }
}
