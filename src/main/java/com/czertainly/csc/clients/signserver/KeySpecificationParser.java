package com.czertainly.csc.clients.signserver;

import com.czertainly.csc.model.signserver.CryptoTokenKeyStatus;
import org.springframework.stereotype.Component;

@Component
public class KeySpecificationParser {

    public KeySpec parse(String keySpecification) {
        String[] lines = keySpecification.split("\n");
        CryptoTokenKeyStatus status = null;
        String keySpec = null;

        for (String line : lines) {
            if (line.startsWith("status:")) {
                boolean assigned = false, certified = false, enabled = false;
                String statusLine = line.replace("status:", "")
                                        .replace("{", "")
                                        .replace("}", "")
                                        .trim();
                for (String statusElement : statusLine.split(",")) {

                    String[] keyValue = statusElement.split("=");
                    String key = keyValue[0].trim();
                    boolean value = Boolean.parseBoolean(keyValue[1].trim());
                    switch (key) {
                        case "assigned":
                            assigned = value;
                            break;
                        case "certified":
                            certified = value;
                            break;
                        case "enabled":
                            enabled = value;
                            break;
                        default:
                            throw new IllegalArgumentException("Unknown status element: " + statusElement);
                    }
                }
                status = new CryptoTokenKeyStatus(certified);

            } else {
                keySpec = line;
            }
        }
        return new KeySpec(keySpec, status);
    }

    public record KeySpec(String keySpecification, CryptoTokenKeyStatus keyStatus) {
    }

}
