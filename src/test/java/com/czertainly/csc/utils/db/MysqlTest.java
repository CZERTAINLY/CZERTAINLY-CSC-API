package com.czertainly.csc.utils.db;

import eu.rekawek.toxiproxy.Proxy;
import eu.rekawek.toxiproxy.ToxiproxyClient;
import org.junit.jupiter.api.AfterEach;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.ToxiproxyContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class MysqlTest {

    private static final Logger logger = LoggerFactory.getLogger(MysqlTest.class);

    @Autowired
    protected TestEntityManager testEntityManager;

    private static final Network network = Network.newNetwork();

    @Container
    private static final ToxiproxyContainer toxiproxy = new ToxiproxyContainer("ghcr.io/shopify/toxiproxy:2.5.0")
            .withNetwork(network);

    @Container
    static MySQLContainer<?> databaseContainer = new MySQLContainer<>("mysql:8.4")
            .withNetwork(network)
            .withNetworkAliases("mysql");

    protected static Proxy proxy;

    @AfterEach
    void tearDown() throws IOException {
        proxy.toxics().getAll().forEach(toxic -> {
            try {
                logger.info("Removing toxic: {}", toxic.getName());
                toxic.remove();
            } catch (IOException e) {
                logger.error("Failed to remove toxic: {}", toxic.getName(), e);
            }
        });
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) throws IOException {
        var toxiproxyClient = new ToxiproxyClient(toxiproxy.getHost(), toxiproxy.getControlPort());
        proxy = toxiproxyClient.createProxy("mysql", "0.0.0.0:8666", "mysql:3306");
        var jdbcUrl = "jdbc:mysql://%s:%d/%s".formatted(toxiproxy.getHost(), toxiproxy.getMappedPort(8666), databaseContainer.getDatabaseName());
        registry.add("spring.datasource.url", () -> jdbcUrl);
        registry.add("spring.datasource.username", databaseContainer::getUsername);
        registry.add("spring.datasource.password", databaseContainer::getPassword);
        registry.add("spring.datasource.hikari.max-lifetime", () -> 10000);
        registry.add("spring.datasource.hikari.connection-timeout", () -> 3000);
        registry.add("spring.datasource.driver-class-name", () -> "com.mysql.cj.jdbc.Driver");
        registry.add("spring.flyway.schemas", () -> "test");
        registry.add("spring.flyway.locations", () -> "classpath:db/migration,classpath:db/specific/{vendor}");
    }
}
