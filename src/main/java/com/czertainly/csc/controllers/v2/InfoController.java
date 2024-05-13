package com.czertainly.csc.controllers.v2;

import com.czertainly.csc.api.common.ErrorDto;
import com.czertainly.csc.api.info.InfoDto;
import com.czertainly.csc.api.signhash.SignHashResponseDto;
import com.czertainly.csc.controllers.exceptions.ServerErrorException;
import com.czertainly.csc.service.InfoService;
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
@Tag(name = "Info", description = "Indo API as defined in the CSC API v2.0.0.2 specification. " +
        "This API is used to retrieve information about the remote serivce.")
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
            description = "Returns information on the remote service and the list of API methods it has implemented. " +
                    "For more information, see the CSC API specification, section `11.1 info`."
    )
    @ApiResponses(
            value = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(schema = @Schema(implementation = InfoDto.class))
                    )
            }
    )
    public InfoDto getInfo() {
        try {
            log.trace("Serving info request.");
            return service.getInfo();
        } catch (Exception e) {
            log.error("Error occurred while getting info.", e);
            throw new ServerErrorException("server_error",
                                           "Unknown error occurred. See the server logs for more information."
            );
        }
    }
}
