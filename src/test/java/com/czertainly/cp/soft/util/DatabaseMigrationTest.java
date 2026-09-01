package com.czertainly.cp.soft.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integrity of the Java migrations.
 *
 * <p>Flyway compares the checksum a migration reports against the one recorded when it was
 * applied, so the published value must never move. The source is allowed to change, and this
 * asserts that any change was deliberate enough to have been recorded.</p>
 */
class DatabaseMigrationTest {

    private static Path sourceOf(DatabaseMigration.JavaMigrationChecksums migration) {
        return Path.of("src/main/java/db/migration", migration.name() + ".java");
    }

    @ParameterizedTest
    @EnumSource(DatabaseMigration.JavaMigrationChecksums.class)
    void migrationSourceIsPresent(DatabaseMigration.JavaMigrationChecksums migration) {
        // A missing file used to be silently ignored, which let a migration disappear without
        // the recorded checksum ever being questioned.
        assertTrue(Files.isRegularFile(sourceOf(migration)),
                "no source for recorded migration " + migration.name());
    }

    @ParameterizedTest
    @EnumSource(DatabaseMigration.JavaMigrationChecksums.class)
    void migrationSourceMatchesItsRecordedChecksum(DatabaseMigration.JavaMigrationChecksums migration)
            throws IOException {
        assertEquals(migration.getSourceChecksum(),
                DatabaseMigration.calculateChecksum(sourceOf(migration).toString()),
                migration.name() + " was edited; record the new source checksum, and leave the "
                        + "published checksum alone so deployed databases still validate");
    }

    @Test
    void publishedChecksumsStayDistinctFromEachOther() {
        // Two migrations reporting the same checksum would make a Flyway mismatch invisible.
        DatabaseMigration.JavaMigrationChecksums[] all =
                DatabaseMigration.JavaMigrationChecksums.values();
        for (int i = 0; i < all.length; i++) {
            for (int j = i + 1; j < all.length; j++) {
                assertNotEquals(all[i].getChecksum(), all[j].getChecksum(),
                        all[i].name() + " and " + all[j].name() + " publish the same checksum");
            }
        }
    }

    @Test
    void everyMigrationSourceIsRecorded() {
        // The reverse direction: a migration added without an entry would report no checksum.
        try (var files = Files.list(Path.of("src/main/java/db/migration"))) {
            files.filter(f -> f.toString().endsWith(".java")).forEach(f -> {
                String name = f.getFileName().toString().replace(".java", "");
                assertTrue(java.util.Arrays.stream(DatabaseMigration.JavaMigrationChecksums.values())
                                .anyMatch(m -> m.name().equals(name)),
                        "migration " + name + " has no recorded checksum");
            });
        } catch (IOException e) {
            throw new IllegalStateException("Cannot list the migration sources", e);
        }
    }
}
