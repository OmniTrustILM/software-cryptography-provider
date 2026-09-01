package com.otilm.cp.soft.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Checksum computation for Java migrations. Flyway compares the value a migration reports
 * against the one recorded in the database, so the way a checksum is derived from source
 * must not drift: line endings and a byte order mark are deliberately ignored.
 */
class DatabaseMigrationChecksumTest {

    @Test
    void byteOrderMarkIsRecognisedAndStripped() {
        assertTrue(DatabaseMigration.isBom('﻿'));
        assertFalse(DatabaseMigration.isBom('a'));

        assertEquals("package db;", DatabaseMigration.filterBomFromString("﻿package db;"));
        assertEquals("package db;", DatabaseMigration.filterBomFromString("package db;"));
        assertEquals("", DatabaseMigration.filterBomFromString(""));
    }

    @ParameterizedTest
    @CsvSource({
            "'line\n', 'line'",
            "'line\r\n', 'line'",
            "'line\r', 'line'",
            "'line\n\n', 'line'",
            "'line', 'line'",
            "'', ''"
    })
    void trailingLineBreaksAreTrimmed(String input, String expected) {
        assertEquals(expected, DatabaseMigration.trimLineBreak(input));
    }

    @Test
    void trimmingNullIsNull() {
        assertNull(DatabaseMigration.trimLineBreak(null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"a", " ", "text"})
    void nonEmptyStringsHaveLength(String value) {
        assertTrue(DatabaseMigration.hasLength(value));
    }

    @Test
    void nullAndEmptyStringsHaveNoLength() {
        assertFalse(DatabaseMigration.hasLength(null));
        assertFalse(DatabaseMigration.hasLength(""));
    }

    @Test
    void checksumIgnoresLineEndingStyle(@TempDir Path dir) throws IOException {
        // A checkout with different line endings must not change a recorded checksum.
        Path unix = dir.resolve("unix.java");
        Path windows = dir.resolve("windows.java");
        Files.write(unix, "class A {\n    int x;\n}\n".getBytes(StandardCharsets.UTF_8));
        Files.write(windows, "class A {\r\n    int x;\r\n}\r\n".getBytes(StandardCharsets.UTF_8));

        assertEquals(DatabaseMigration.calculateChecksum(unix.toString()),
                DatabaseMigration.calculateChecksum(windows.toString()));
    }

    @Test
    void checksumIgnoresALeadingByteOrderMark(@TempDir Path dir) throws IOException {
        Path plain = dir.resolve("plain.java");
        Path withBom = dir.resolve("bom.java");
        Files.write(plain, "class A {}\n".getBytes(StandardCharsets.UTF_8));
        Files.write(withBom, "﻿class A {}\n".getBytes(StandardCharsets.UTF_8));

        assertEquals(DatabaseMigration.calculateChecksum(plain.toString()),
                DatabaseMigration.calculateChecksum(withBom.toString()));
    }

    @Test
    void changingContentChangesTheChecksum(@TempDir Path dir) throws IOException {
        Path before = dir.resolve("before.java");
        Path after = dir.resolve("after.java");
        Files.write(before, "class A { int x; }\n".getBytes(StandardCharsets.UTF_8));
        Files.write(after, "class A { int y; }\n".getBytes(StandardCharsets.UTF_8));

        assertNotEquals(DatabaseMigration.calculateChecksum(before.toString()),
                DatabaseMigration.calculateChecksum(after.toString()));
    }

    @Test
    void everyRecordedMigrationChecksumIsReadable() {
        for (DatabaseMigration.JavaMigrationChecksums checksum
                : DatabaseMigration.JavaMigrationChecksums.values()) {
            assertNotEquals(0, checksum.getChecksum(), checksum.name() + " has no recorded checksum");
        }
    }
}
