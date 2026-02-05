package com.czertainly.csc.providers.sanitization;

import org.springframework.stereotype.Component;

/**
 * Sanitizes Distinguished Names (DNs) and Subject Alternative Names (SAN) according to EJBCA DN formatting requirements.
 * <p>
 * According to the EJBCA DN Requirements, the following characters must be escaped in DNs:
 * <ul>
 *   <li>, (comma)</li>
 *   <li>+ (plus)</li>
 *   <li>= (equals)</li>
 * </ul>
 *
 * Through testing, it was determined that EJBCA also require escaping of the following characters in DNs:
 * <ul>
 *   <li># (double quotes)</li>
 *   <li>" (double quote)</li>
 *   <li>\ (backslash)</li>
 * </ul>
 *
 * The same rules apply to SAN values.
 * @see <a href="https://docs.keyfactor.com/ejbca/latest/subject-distinguished-names">EJBCA DN Documentation</a>
 */
@Component
public class EjbcaDnAndSanAndSanSanitizer implements DnAndSanSanitizer {

    /**
     * Escapes special characters in a DN component value according to RFC 4514.
     * @param value the raw value to escape
     * @return escaped value safe for use in EJBCA DN
     * @throws IllegalArgumentException if value is null
     */
    @Override
    public String escapeValue(String value) {
        if (value == null) {
            throw new IllegalArgumentException("DN component value cannot be null");
        }

        if (value.isEmpty()) {
            return value;
        }

        StringBuilder escaped = new StringBuilder(value.length());

        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);

            switch (c) {
                case '\\':
                    escaped.append("\\\\");
                    break;
                case ',':
                    escaped.append("\\,");
                    break;
                case '+':
                    escaped.append("\\+");
                    break;
                case '=':
                    escaped.append("\\=");
                    break;

                case '#':
                    if (i == 0) {
                        escaped.append("\\#");
                    } else {
                        escaped.append("#");
                    }
                    break;
                case '"':
                    escaped.append("\\\"");
                    break;
                default:
                    escaped.append(c);
                    break;
            }
        }

        return escaped.toString();
    }
}
