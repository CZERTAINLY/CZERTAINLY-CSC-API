package com.czertainly.csc.controllers.v2;

import com.czertainly.csc.api.auth.CscAuthenticationToken;
import com.czertainly.csc.api.credentials.CredentialDto;
import com.czertainly.csc.api.credentials.CredentialsListDto;
import com.czertainly.csc.api.credentials.GetCredentialInfoDto;
import com.czertainly.csc.api.credentials.ListCredentialsRequestDto;
import com.czertainly.csc.api.mappers.credentials.CredentialInfoRequestMapper;
import com.czertainly.csc.api.mappers.credentials.CredentialsListRequestMapper;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.components.DateConverter;
import com.czertainly.csc.controllers.exceptions.InternalErrorException;
import com.czertainly.csc.model.csc.requests.CredentialInfoRequest;
import com.czertainly.csc.model.csc.requests.ListCredentialsRequest;
import com.czertainly.csc.service.credentials.CredentialsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("csc/v2/credentials")
@PreAuthorize("hasAuthority('SCOPE_credential') || hasAuthority('SCOPE_service')")
@Tag(name = "Credentials", description = "Credentials API as defined in the CSC API v2.0.0.2 specification. " +
        "This API is used to get information about the existing user credentials.")
@SecurityRequirements(value = {
        @SecurityRequirement(name = "BearerAuthCredential"),
})
public class CredentialsController {

    private static final Logger logger = LoggerFactory.getLogger(CredentialsController.class);

    private final CredentialsService credentialsService;
    private final DateConverter dateConverter;

    private final CredentialInfoRequestMapper credentialInfoRequestMapper;
    private final CredentialsListRequestMapper credentialsListRequestMapper;

    public CredentialsController(CredentialsService credentialsService, DateConverter dateConverter,
                                 CredentialInfoRequestMapper credentialInfoRequestMapper,
                                 CredentialsListRequestMapper credentialsListRequestMapper
    ) {
        this.credentialsService = credentialsService;
        this.dateConverter = dateConverter;
        this.credentialInfoRequestMapper = credentialInfoRequestMapper;
        this.credentialsListRequestMapper = credentialsListRequestMapper;
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
    public CredentialsListDto listCredentials(
            @RequestBody ListCredentialsRequestDto requestDto,
            Authentication authentication
    ) {
        CscAuthenticationToken token = castTokenOrThrow(authentication);
        ListCredentialsRequest request = credentialsListRequestMapper.map(requestDto, token);
        return credentialsService
                .listUserCredentials(request)
                .map(credentials -> CredentialsListDto.from(credentials, dateConverter))
                .mapError(e -> e.extend("Failed to list credentials of the user %s", requestDto.userID()))
                .consumeError(this::logAndThrowError)
                .unwrap();
    }

    @RequestMapping(path = "info", method = RequestMethod.POST, produces = "application/json")
    @Operation(summary = "Credentials Info",
            description = "Retrieves the credential. For more information, see the CSC API specification, " +
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
    public CredentialDto credentialInfo(
            @RequestBody GetCredentialInfoDto getCredentialInfoDto,
        Authentication authentication
    ) {
        CscAuthenticationToken token = castTokenOrThrow(authentication);
        CredentialInfoRequest request = credentialInfoRequestMapper.map(getCredentialInfoDto, token);
        return credentialsService
                .getCredential(request)
                .map(credential -> CredentialDto.fromModel(credential, dateConverter))
                .mapError(e -> e.extend("Failed to obtain credential info for credential %s",
                                        getCredentialInfoDto.credentialID()
                ))
                .consumeError(this::logAndThrowError)
                .unwrap();
    }

    private static CscAuthenticationToken castTokenOrThrow(Authentication authentication) {
        CscAuthenticationToken token;
        if (authentication instanceof CscAuthenticationToken) {
            token = (CscAuthenticationToken) authentication;
        } else {
            throw new InternalErrorException("Failed to authenticate list credentials request because authentication" +
                                                     " object must be of type CscAuthenticationToken but was " +
                                                     authentication.getClass().getSimpleName());
        }
        return token;
    }

    private void logAndThrowError(TextError error) {
        logger.error(error.toString());
        throw new InternalErrorException(error.toString());
    }
}
