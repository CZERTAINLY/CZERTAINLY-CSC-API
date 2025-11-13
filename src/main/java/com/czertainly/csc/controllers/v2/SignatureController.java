package com.czertainly.csc.controllers.v2;

import com.czertainly.csc.api.auth.CscAuthenticationToken;
import com.czertainly.csc.api.auth.SignatureActivationData;
import com.czertainly.csc.api.auth.TokenValidator;
import com.czertainly.csc.api.common.ErrorDto;
import com.czertainly.csc.api.mappers.signatures.SignDocResponseMapper;
import com.czertainly.csc.api.mappers.signatures.SignDocValidatingRequestMapper;
import com.czertainly.csc.api.mappers.signatures.SignHashResponseMapper;
import com.czertainly.csc.api.mappers.signatures.SignHashValidatingRequestMapper;
import com.czertainly.csc.api.signdoc.SignDocRequestDto;
import com.czertainly.csc.api.signdoc.SignDocResponseDto;
import com.czertainly.csc.api.signhash.SignHashRequestDto;
import com.czertainly.csc.api.signhash.SignHashResponseDto;
import com.czertainly.csc.common.result.TextError;
import com.czertainly.csc.controllers.exceptions.InternalErrorException;
import com.czertainly.csc.model.SignDocParameters;
import com.czertainly.csc.model.SignHashParameters;
import com.czertainly.csc.signing.SignatureFacade;
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
@SecurityRequirements(value = {
        @SecurityRequirement(name = "BearerAuthSignature"),
})
public class SignatureController {

    private static final Logger logger = LoggerFactory.getLogger(SignatureController.class);

    final SignatureFacade signatureFacade;

    final TokenValidator tokenValidator;
    final SignHashValidatingRequestMapper signHashValidationRequestMapper;
    final SignDocValidatingRequestMapper signDocValidatingRequestMapper;
    final SignDocResponseMapper signDocResponseMapper;
    private final SignHashResponseMapper signHashResponseMapper;


    public SignatureController(
            SignHashValidatingRequestMapper signHashValidationRequestMapper,
            TokenValidator tokenValidator, SignatureFacade signatureFacade,
            SignDocValidatingRequestMapper signDocValidatingRequestMapper,
            SignDocResponseMapper signDocResponseMapper,
            SignHashResponseMapper signHashResponseMapper
    ) {
        this.tokenValidator = tokenValidator;
        this.signHashValidationRequestMapper = signHashValidationRequestMapper;
        this.signatureFacade = signatureFacade;
        this.signDocValidatingRequestMapper = signDocValidatingRequestMapper;
        this.signDocResponseMapper = signDocResponseMapper;
        this.signHashResponseMapper = signHashResponseMapper;
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
        logger.trace("Serving signHash request.");
        SignHashParameters parameters = signHashValidationRequestMapper
                    .map(signHashRequest, getSadIfAvailable(authentication));

        return signatureFacade.signHashes(parameters)
                              .flatMap(signHashResponseMapper::map)
                              .mapError(e -> e.extend("Failed to sign the document."))
                              .consumeError(this::logAndThrowError)
                              .unwrap();
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
    public SignDocResponseDto signDoc(@RequestBody SignDocRequestDto signDocRequest, Authentication authentication) {
        logger.trace("Serving signDoc request.");
        SignDocParameters request = signDocValidatingRequestMapper
                .map(signDocRequest, getSadIfAvailable(authentication));
        return signatureFacade.signDocuments(request, ((CscAuthenticationToken) authentication))
                              .flatMap(signDocResponseMapper::map)
                              .mapError(e -> e.extend("Failed to sign the document."))
                              .consumeError(this::logAndThrowError)
                              .unwrap();
    }

    private SignatureActivationData getSadIfAvailable(Authentication authentication) {
        if (authentication instanceof CscAuthenticationToken) {
            return ((CscAuthenticationToken) authentication).getSignatureActivationData();
        }
        return null;
    }

    private void logAndThrowError(TextError error) {
        logger.error(error.toString());
        throw new InternalErrorException(error.toString());
    }
}
