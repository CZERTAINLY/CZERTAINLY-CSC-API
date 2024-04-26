package com.czertainly.signserver.csc.controllers.v2;

import com.czertainly.signserver.csc.api.auth.CscAuthenticationToken;
import com.czertainly.signserver.csc.api.auth.SignatureActivationData;
import com.czertainly.signserver.csc.api.auth.TokenValidator;
import com.czertainly.signserver.csc.api.signdoc.SignDocRequestDto;
import com.czertainly.signserver.csc.api.signdoc.SignDocResponseDto;
import com.czertainly.signserver.csc.api.signhash.SignHashRequestDto;
import com.czertainly.signserver.csc.api.signhash.SignHashResponseDto;
import com.czertainly.signserver.csc.common.ApplicationException;
import com.czertainly.signserver.csc.controllers.exceptions.BadRequestException;
import com.czertainly.signserver.csc.controllers.exceptions.ServerErrorException;
import com.czertainly.signserver.csc.model.mappers.SignDocResponseMapper;
import com.czertainly.signserver.csc.model.mappers.SignDocValidatingRequestMapper;
import com.czertainly.signserver.csc.model.mappers.SignHashValidatingRequestMapper;
import com.czertainly.signserver.csc.signing.DocumentSigning;
import com.czertainly.signserver.csc.signing.SignatureFacade;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("csc/v2/signatures")
@PreAuthorize("hasAuthority('SCOPE_credential') || hasAuthority('SCOPE_service')")
public class SignatureController {

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

    @PostMapping(path = "/signHash")
    public SignHashResponseDto signHash(@RequestBody SignHashRequestDto signHashRequest,
                                        Authentication authentication
    ) {
        return signHashValidationRequestMapper
                .map(signHashRequest, getSadIfAvailable(authentication))
                .with(
                        parameters -> new SignHashResponseDto(
                                List.of("signature1", "signature2")),
                        error -> {
                            throw new BadRequestException(error.error(),
                                                          error.description()
                            );
                        }
                );
    }

    @PostMapping(path = "/signDoc")
    public SignDocResponseDto signHash(@RequestBody SignDocRequestDto signDocRequest,
                                       Authentication authentication
    ) {

        return signDocValidatingRequestMapper
                .map(signDocRequest, getSadIfAvailable(authentication))
                .with(
                        parameters -> signatureFacade.signDocuments(parameters).with(
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
    }

    private SignatureActivationData getSadIfAvailable(Authentication authentication) {
        if (authentication instanceof CscAuthenticationToken) {
            return ((CscAuthenticationToken) authentication).getSignatureActivationData();
        }
        return null;
    }
}
