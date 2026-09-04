package com.otilm.cp.soft.logging;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The trace a caller states is what ties everything said while serving its request to the request it came from, so a
 * header that can be read is read and one that cannot leaves the request with a trace of its own rather than with a
 * value the log schema would refuse.
 */
class TraceParentTest {

    private static final String TRACE = "4c8f7c10d5a6d0ae4bbf6b6e8b0cd8a1";

    private static final String SPAN = "f1a2b3c4d5e6f789";

    @Test
    void readsTheTraceTheCallerStated() {
        // given
        // when
        TraceParent trace = TraceParent.of("00-" + TRACE + "-" + SPAN + "-01");

        // then
        assertEquals(TRACE, trace.traceId());
        assertEquals(SPAN, trace.spanId());
        assertEquals("01", trace.flags());
    }

    /**
     * The first version states these fields and nothing after them, so anything after them means the header is not that
     * version's and nothing is read from it. A trailing separator counts as something after them.
     */
    @Test
    void readsNoTraceFromTheFirstVersionStatingAnythingAfterItsFields() {
        // given
        // when
        TraceParent trace = TraceParent.of("00-" + TRACE + "-" + SPAN + "-01-extra");

        // then
        assertNotEquals(TRACE, trace.traceId());
        assertEquals("00", trace.flags());
    }

    /** A later version states these fields first and its own after them, so what is here is still read. */
    @Test
    void readsATraceStatedByAVersionItDoesNotKnow() {
        // given
        // when
        TraceParent trace = TraceParent.of("cc-" + TRACE + "-" + SPAN + "-01-something-else");

        // then
        assertEquals(TRACE, trace.traceId());
        assertEquals(SPAN, trace.spanId());
    }

    /** The header carries a byte of flags; the schema accepts the recorded bit and nothing else. */
    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource({"00,00", "01,01", "02,00", "03,01", "ff,01", "fe,00"})
    void readsOnlyWhetherTheTraceIsBeingRecorded(String stated, String written) {
        // given
        // when
        TraceParent trace = TraceParent.of("00-" + TRACE + "-" + SPAN + "-" + stated);

        // then
        assertEquals(written, trace.flags());
    }

    @ParameterizedTest(name = "\"{0}\"")
    @ValueSource(strings = {
            "",
            "not a trace parent",
            "00-4c8f7c10d5a6d0ae4bbf6b6e8b0cd8a1",
            "00-4C8F7C10D5A6D0AE4BBF6B6E8B0CD8A1-f1a2b3c4d5e6f789-01",
            "00-4c8f7c10d5a6d0ae4bbf6b6e8b0cd8a1-F1A2B3C4D5E6F789-01",
            "00-00000000000000000000000000000000-f1a2b3c4d5e6f789-01",
            "00-4c8f7c10d5a6d0ae4bbf6b6e8b0cd8a1-0000000000000000-01",
            "ff-4c8f7c10d5a6d0ae4bbf6b6e8b0cd8a1-f1a2b3c4d5e6f789-01",
            "0-4c8f7c10d5a6d0ae4bbf6b6e8b0cd8a1-f1a2b3c4d5e6f789-01",
            "00-4c8f7c10d5a6d0ae4bbf6b6e8b0cd8a1-f1a2b3c4d5e6f789-1",
            "00-4c8f7c10d5a6d0ae4bbf6b6e8b0cd8a1-f1a2b3c4d5e6f789-zz",
            "00-4c8f7c10d5a6d0ae4bbf6b6e8b0cd8a1x-f1a2b3c4d5e6f789-01",
            "00-4c8f7c10d5a6d0ae4bbf6b6e8b0cd8a1-f1a2b3c4d5e6f789-01-extra",
            "00-4c8f7c10d5a6d0ae4bbf6b6e8b0cd8a1-f1a2b3c4d5e6f789-01-",
            "00-4c8f7c10d5a6d0ae4bbf6b6e8b0cd8a1-f1a2b3c4d5e6f789-01 trailing"})
    void givesARequestATraceOfItsOwnWhenItStatesNoneThatCanBeRead(String stated) {
        // given
        // when
        TraceParent trace = TraceParent.of(stated);

        // then
        assertTrue(trace.traceId().matches("[0-9a-f]{32}"), () -> "not a trace identifier: " + trace.traceId());
        assertTrue(trace.spanId().matches("[0-9a-f]{16}"), () -> "not a span identifier: " + trace.spanId());
        assertEquals("00", trace.flags(), "nothing is recording a trace of this request's own");
        assertNotEquals(TRACE, trace.traceId());
    }

    @ParameterizedTest
    @NullSource
    void givesARequestATraceOfItsOwnWhenItStatesNothing(String stated) {
        // given
        // when
        TraceParent trace = TraceParent.of(stated);

        // then
        assertTrue(trace.traceId().matches("[0-9a-f]{32}"));
        assertTrue(trace.spanId().matches("[0-9a-f]{16}"));
    }

    /** Two requests that state nothing are two traces, or everything said about either gathers with the other. */
    @Test
    void givesEachSuchRequestATraceOfItsOwn() {
        // given
        // when
        TraceParent first = TraceParent.of(null);
        TraceParent second = TraceParent.of(null);

        // then
        assertNotEquals(first.traceId(), second.traceId());
        assertNotEquals(first.spanId(), second.spanId());
    }

    /** A header stated with space around it is still the header. */
    @Test
    void readsATraceStatedWithSpaceAroundIt() {
        // given
        // when
        TraceParent trace = TraceParent.of("  00-" + TRACE + "-" + SPAN + "-01  ");

        // then
        assertEquals(TRACE, trace.traceId());
    }
}
