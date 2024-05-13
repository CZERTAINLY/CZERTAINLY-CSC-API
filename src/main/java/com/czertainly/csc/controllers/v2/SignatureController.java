package com.czertainly.csc.controllers.v2;

import com.czertainly.csc.api.auth.CscAuthenticationToken;
import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.api.auth.TokenValidator;
import com.czertainly.csc.api.common.ErrorDto;
import com.czertainly.csc.api.signdoc.SignDocRequestDto;
import com.czertainly.csc.api.signdoc.SignDocResponseDto;
import com.czertainly.csc.api.signhash.SignHashRequestDto;
import com.czertainly.csc.api.signhash.SignHashResponseDto;
import com.czertainly.csc.common.exceptions.InputDataException;
import com.czertainly.csc.common.exceptions.RemoteSystemException;
import com.czertainly.csc.controllers.exceptions.BadRequestException;
import com.czertainly.csc.controllers.exceptions.ServerErrorException;
import com.czertainly.csc.model.mappers.SignDocResponseMapper;
import com.czertainly.csc.model.mappers.SignDocValidatingRequestMapper;
import com.czertainly.csc.model.mappers.SignHashValidatingRequestMapper;
import com.czertainly.csc.signing.SignatureFacade;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("csc/v2/signatures")
@PreAuthorize("hasAuthority('SCOPE_credential') || hasAuthority('SCOPE_service')")
@Tag(name = "Signatures", description = "Signatures API as defined in the CSC API v2.0.0.2 specification. " +
        "This API is used to sign documents and hashes.")
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
        })
public class SignatureController {

    private static final Logger log = LoggerFactory.getLogger(SignatureController.class);

    final SignatureFacade signatureFacade;

    final TokenValidator tokenValidator;
    final SignHashValidatingRequestMapper signHashValidationRequestMapper;
    final SignDocValidatingRequestMapper signDocValidatingRequestMapper;
    final SignDocResponseMapper signDocResponseMapper;


    public SignatureController(
            SignHashValidatingRequestMapper signHashValidationRequestMapper,
            TokenValidator tokenValidator, SignatureFacade signatureFacade,
            SignDocValidatingRequestMapper signDocValidatingRequestMapper,
            SignDocResponseMapper signDocResponseMapper
    ) {
        this.tokenValidator = tokenValidator;
        this.signHashValidationRequestMapper = signHashValidationRequestMapper;
        this.signatureFacade = signatureFacade;
        this.signDocValidatingRequestMapper = signDocValidatingRequestMapper;
        this.signDocResponseMapper = signDocResponseMapper;
    }

    @RequestMapping(
            path = "/signHash",
            method = RequestMethod.POST,
            consumes = "application/json",
            produces = "application/json"
    )
    @Operation(summary = "Sign hash",
            description = "Calculate a raw digital signature from one or more hash values. For more information, " +
                    "see the CSC API specification, section `11.10 signatures/signHash`."
    )
    @ApiResponses(
            value = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(schema = @Schema(implementation = SignHashResponseDto.class))
                    )
            }
    )
    public SignHashResponseDto signHash(@RequestBody SignHashRequestDto signHashRequest,
                                        Authentication authentication
    ) {
        try {
            return signHashValidationRequestMapper
                    .map(signHashRequest, getSadIfAvailable(authentication))
                    .with(
                            parameters -> new SignHashResponseDto(
                                    List.of("signature1", "signature2"), null),
                            error -> {
                                throw new BadRequestException(error.error(),
                                                              error.description()
                                );
                            }
                    );
        } catch (RemoteSystemException e) {
            log.error("An error occurred when communicating with a remote system.", e);
            throw new ServerErrorException("Unexpected error occurred.", e.getMessage());
        } catch (BadRequestException e) {
            throw e;
        } catch (Exception e) {
            log.error("An unexpected error occurred.", e);
            throw new ServerErrorException("Unexpected error occurred.", e.getMessage());
        }
    }

    @RequestMapping(
            path = "/signDoc",
            method = RequestMethod.POST,
            consumes = "application/json",
            produces = "application/json"
    )
    @Operation(
            summary = "Sign document",
            description = "Creates one or more AdES signatures for documents or document digests. For more information, " +
                    "see the CSC API specification, section `11.11 signature/signDoc`.")
    @ApiResponses(
            value = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(schema = @Schema(implementation = SignDocResponseDto.class))
                    ),
                    @ApiResponse(
                            responseCode = "403",
                            description = "Forbidden",
                            content = @Content(schema = @Schema(implementation = ErrorDto.class))
                    ),
            }
    )
    public SignDocResponseDto signDoc(@RequestBody SignDocRequestDto signDocRequest,
                                      Authentication authentication
    ) {
        try {
            return signDocValidatingRequestMapper
                    .map(signDocRequest, getSadIfAvailable(authentication))
                    .with(
                            parameters -> signatureFacade.signDocuments(
                                    parameters,
                                    ((CscAuthenticationToken) authentication)
                            ).with(
                                    signatures -> signDocResponseMapper.map(signatures).with(
                                            signDocResponseDto -> signDocResponseDto,
                                            error -> {
                                                throw new ServerErrorException(error.error(), error.description());
                                            }

                                    ),
                                    error -> {
                                        throw new ServerErrorException(error.error(), error.description());
                                    }
                            ),
                            error -> {
                                throw new BadRequestException(error.error(),
                                                              error.description()
                                );
                            }
                    );
        } catch (InputDataException e) {
            log.error("Invalid input data provided.", e);
            throw new BadRequestException("invalid_request", e.getMessage());
        } catch (RemoteSystemException e) {
            log.error("An error occurred when communicating with a remote system.", e);
            throw new ServerErrorException("Unexpected error occurred.", e.getMessage());
        } catch (BadRequestException e) {
            throw e;
        } catch (Exception e) {
            log.error("An unexpected error occurred.", e);
            throw new ServerErrorException("Unexpected error occurred.", e.getMessage());
        }

    }

    private SignatureActivationData getSadIfAvailable(Authentication authentication) {
        if (authentication instanceof CscAuthenticationToken) {
            return ((CscAuthenticationToken) authentication).getSignatureActivationData();
        }
        return null;
    }
}
