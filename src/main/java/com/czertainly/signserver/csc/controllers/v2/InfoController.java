package com.czertainly.signserver.csc.controllers.v2;

import com.czertainly.signserver.csc.api.info.InfoDto;
import com.czertainly.signserver.csc.api.signhash.SignHashResponseDto;
import com.czertainly.signserver.csc.controllers.exceptions.ServerErrorException;
import com.czertainly.signserver.csc.service.InfoService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("csc/v2/info")
@Tag(name = "Info", description = "Returns information about the remote service and the list of the API methods it supports.")
@ApiResponses(
        value = {
                @ApiResponse(
                        responseCode = "500",
                        description = "Internal Server Error",
                        content = @Content
                )
        }
)
public class InfoController {

    private static final Logger log = LoggerFactory.getLogger(InfoController.class);

    private final InfoService service;

    public InfoController(InfoService service) {
        this.service = service;
    }

    @RequestMapping(method = RequestMethod.GET, produces = "application/json")
    @Operation(summary = "Get Info",
            description = "Returns information on the remote service and the list of API methods it has implemented."
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
    public InfoDto getInfo() {
        try {
            return service.getInfo();
        } catch (Exception e) {
            log.error("Error occurred while getting info.", e);
            throw new ServerErrorException("server_error",
                                           "Unknown error occurred. See the server logs for more information."
            );
        }
    }
}
