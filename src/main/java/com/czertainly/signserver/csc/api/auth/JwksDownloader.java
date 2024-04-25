package com.czertainly.signserver.csc.api.auth;

import com.czertainly.signserver.csc.api.auth.exceptions.JwksDownloadException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;

@Component
public class JwksDownloader {

    private final Logger logger = LogManager.getLogger(JwksDownloader.class);

    private final URL jwksUrl;

    public JwksDownloader(@Value("${idp.jwksUri}") String jwksUri) {
        try {
            this.jwksUrl = new URI(jwksUri).toURL();
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid JWKS URI", e);
        }
    }

    public String download() throws JwksDownloadException {
        HttpsURLConnection con = null;
        BufferedInputStream br = null;
        try {
            con = (HttpsURLConnection) jwksUrl.openConnection();
            br = new BufferedInputStream(con.getInputStream());
            return new String(br.readAllBytes(), StandardCharsets.UTF_8);

        } catch (IOException e) {
            throw new JwksDownloadException("Failed to download certificates from jwks url.", e);
        } catch (ClassCastException e) {
            throw new JwksDownloadException("The connection created is not an HTTPS connection." +
                                                    " The JWKS URL must use HTTPS.");
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    logger.error("Error closing BufferedReader", e);
                }
            }
            if (con != null) {
                con.disconnect();
            }
        }
    }
}

