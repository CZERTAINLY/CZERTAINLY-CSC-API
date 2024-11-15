package com.czertainly.csc.api.mappers;

import com.czertainly.csc.api.common.StructuredClientDataDto;
import com.czertainly.csc.common.exceptions.InvalidInputDataException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

@Component
public class StructuredClientDataMapper {

    private static final Logger logger = LoggerFactory.getLogger(StructuredClientDataMapper.class);
    private final ObjectMapper objectMapper;

    public StructuredClientDataMapper(Jackson2ObjectMapperBuilder objectMapperBuilder) {
        this.objectMapper = objectMapperBuilder.build();
    }

    public StructuredClientData map(String clientData) {

        if (clientData == null || clientData.isBlank()) {
            return StructuredClientData.empty();
        }

        try {
            StructuredClientDataDto data = objectMapper.readValue(clientData, StructuredClientDataDto.class);
            if (data.getSessionId() != null) {
                try {
                    UUID sessionId = UUID.fromString(data.getSessionId());
                    return StructuredClientData.of(sessionId, data.getClientData());
                } catch (IllegalArgumentException e) {
                    logger.debug("Failed to parse session ID string '{}' to valid UUID.", data.getSessionId());
                    throw new InvalidInputDataException("Invalid format of a session id provided in clientData.");
                }
            } else {
                return StructuredClientData.of(data.getClientData());
            }

        } catch (Exception e) {
            logger.debug("Failed to parse client data '{}' to StructuredClientData. Assuming plain String clientData",
                         clientData
            );
            return StructuredClientData.of(clientData);
        }
    }

    public record StructuredClientData(Optional<UUID> session, Optional<String> clientData) {

        public static StructuredClientData empty() {
            return new StructuredClientData(Optional.empty(), Optional.empty());
        }

        public static StructuredClientData of(UUID session, String clientData) {
            return new StructuredClientData(Optional.of(session), Optional.of(clientData));
        }

        public static StructuredClientData of(String clientData) {
            return new StructuredClientData(Optional.empty(), Optional.of(clientData));
        }
    }
}
