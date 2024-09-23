package com.czertainly.csc.api.auth;

import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.czertainly.csc.utils.jwt.Constants.JWKS_STRING;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
class JwksRepositoryTest {

    @Mock
    private JwksDownloader jwksDownloader;

    @Inject
    private JwksParser jwksParser = new JwksParser();

    @InjectMocks
    JwksRepository jwksRepository;

    @BeforeEach
    void setUp() {
        when(jwksDownloader.download()).thenReturn(JWKS_STRING);
    }

    @Test
    void getKey() {
        jwksRepository.getKey("kid", "usage");
    }



}