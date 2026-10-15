package com.otilm.cp.soft;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.CoreMigrationType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.flyway.autoconfigure.FlywayMigrationStrategy;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Spring Boot runs Flyway only from its own auto-configuration module, so a connector missing it keeps a stale schema.
 * The migrations are written for PostgreSQL, so the test records what startup hands to Flyway instead of applying it.
 */
@SpringBootTest(properties = {
        "spring.flyway.enabled=true",
        "spring.datasource.url=jdbc:hsqldb:mem:flywayAtStartup;sql.syntax_pgs=true"})
class FlywayAtStartupTest {

    private RecordingMigrationStrategy strategy;

    @Autowired
    void setStrategy(RecordingMigrationStrategy strategy) {
        this.strategy = strategy;
    }

    @Test
    void startupMigratesWithEverySqlAndJavaMigration() {
        // when
        Flyway started = strategy.started;

        // then
        assertNotNull(started, "Flyway runs when the connector starts");
        Set<CoreMigrationType> pending = Arrays
                .stream(started.info().pending())
                .map(migration -> (CoreMigrationType) migration.getType())
                .collect(Collectors.toSet());
        assertEquals(Set.of(CoreMigrationType.SQL, CoreMigrationType.JDBC), pending);
    }

    @TestConfiguration
    static class RecordingMigrationStrategyConfiguration {

        @Bean
        RecordingMigrationStrategy recordingMigrationStrategy() {
            return new RecordingMigrationStrategy();
        }
    }

    static class RecordingMigrationStrategy implements FlywayMigrationStrategy {

        private Flyway started;

        @Override
        public void migrate(Flyway flyway) {
            started = flyway;
        }
    }
}
