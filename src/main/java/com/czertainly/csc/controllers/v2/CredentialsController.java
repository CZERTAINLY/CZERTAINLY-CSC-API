package com.czertainly.csc.controllers.v2;

import com.czertainly.csc.api.common.ErrorDto;
import com.czertainly.csc.api.credentials.*;
import com.czertainly.csc.api.mappers.credentials.CredentialInfoRequestMapper;
import com.czertainly.csc.api.signhash.SignHashResponseDto;
import com.czertainly.csc.components.DateConverter;
import com.czertainly.csc.controllers.exceptions.BadRequestException;
import com.czertainly.csc.controllers.exceptions.ServerErrorException;
import com.czertainly.csc.model.csc.Credential;
import com.czertainly.csc.model.csc.requests.CredentialInfoRequest;
import com.czertainly.csc.service.CredentialsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("csc/v2/credentials")
@Tag(name = "Credentials", description = "Credentials API as defined in the CSC API v2.0.0.2 specification. " +
        "This API is used to retrieve information about the credentials associated to user.")
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
                ),
                @ApiResponse(
                        responseCode = "501",
                        description = "Not Implemented",
                        content = @Content
                ),
        }
)
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
    @Operation(summary = "List Credentials",
            description = "Returns the list of credentials associated with a user identifier. For more information, " +
                    "see the CSC API specification, section `11.4 credentials/list`."
    )
    @ApiResponses(
            value = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(schema = @Schema(implementation = CredentialsListDto.class))
                    )
            }
    )
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
    @Operation(summary = "Credentials Info",
            description = "Returns information on a signing credential, its associated certificate and a description of " +
                    "the supported authorization mechanism. For more information, see the CSC API specification, " +
                    "section `11.5 credentials/info`."
    )
    @ApiResponses(
            value = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(schema = @Schema(implementation = CredentialDto.class))
                    )
            }
    )
    public CredentialDto credentialInfo(@RequestBody GetCredentialInfoDto getCredentialInfoDto) {
        return credentialInfoRequestMapper
                .map(getCredentialInfoDto, null)
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
