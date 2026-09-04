package com.otilm.cp.soft.metrics;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The memory a process is resident in is the one required reading no part of the JVM reports, so it is read from where
 * the operating system publishes it. What that says is a stated format, and reading it wrongly would report a figure
 * that looks like a measurement.
 */
class RequiredMetricsTest {

    @TempDir
    Path directory;

    @Test
    void readsTheResidentMemoryAProcessStates() throws IOException {
        // given
        Path status = Files.writeString(directory.resolve("status"), """
                Name:\tjava
                VmPeak:\t 2048000 kB
                VmRSS:\t  148372 kB
                Threads:\t33
                """);

        // when
        double bytes = RequiredMetrics.residentBytes(status);

        // then
        assertEquals(148372L * 1024, bytes);
    }

    /** A system that does not publish it is reported as nothing, since a made-up figure would be worse. */
    @Test
    void reportsNothingWhereTheSystemDoesNotPublishIt() {
        // given
        Path absent = directory.resolve("no-such-status");

        // when
        // then
        assertEquals(0, RequiredMetrics.residentBytes(absent));
    }

    @Test
    void reportsNothingWhereTheReadingIsNotThere() throws IOException {
        // given
        Path status = Files.writeString(directory.resolve("status"), "Name:\tjava\nThreads:\t33\n");

        // when
        // then
        assertEquals(0, RequiredMetrics.residentBytes(status));
    }

    @Test
    void reportsNothingWhereTheReadingCannotBeRead() throws IOException {
        // given
        Path status = Files.writeString(directory.resolve("status"), "VmRSS:\tplenty kB\n");

        // when
        // then
        assertEquals(0, RequiredMetrics.residentBytes(status));
    }
}
