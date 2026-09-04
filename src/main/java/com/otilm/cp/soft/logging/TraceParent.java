package com.otilm.cp.soft.logging;

import java.security.SecureRandom;
import java.util.regex.Pattern;

/**
 * The trace a request is part of, as the caller stated it.
 *
 * <p>
 * A caller states it in a {@code traceparent} header: a version, the identifier of the trace as a whole, the identifier
 * of the span the caller was in when it made the request, and the flags of that trace. A request that states none is
 * given one of its own, so that everything said while serving it can still be gathered together.
 * </p>
 *
 * <p>
 * What is read out is held to the shapes the log schema states rather than only to the ones the header allows. The
 * flags are the exception: the header carries a byte of them, of which only the sampled bit is defined, while the
 * schema accepts that bit alone — so the rest are dropped rather than written as something the schema refuses.
 * </p>
 */
public final class TraceParent {

    /** The shapes the schema states: a trace identifier of sixteen bytes and a span of eight, in lower-case hex. */
    private static final Pattern TRACE_ID_SHAPE = Pattern.compile("[0-9a-f]{32}");

    private static final Pattern SPAN_ID_SHAPE = Pattern.compile("[0-9a-f]{16}");

    private static final Pattern FLAGS_SHAPE = Pattern.compile("[0-9a-f]{2}");

    private static final Pattern VERSION_SHAPE = Pattern.compile("[0-9a-f]{2}");

    /** A version of the header that says nothing can be read from it. */
    private static final String NO_VERSION = "ff";

    /** The first version, which states these fields and nothing after them. */
    private static final String FIRST_VERSION = "00";

    private static final Pattern FIRST_VERSION_SHAPE = Pattern.compile("00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}");

    /** An identifier of nothing but zeros identifies nothing. */
    private static final String NO_TRACE = "0".repeat(32);

    private static final String NO_SPAN = "0".repeat(16);

    /** The bit of the flags the schema accepts, which says whether the trace is being recorded. */
    private static final int SAMPLED = 0x01;

    private static final String SAMPLED_FLAG = "01";

    private static final String NOT_SAMPLED_FLAG = "00";

    /** The fields the first version of the header states, which any later version states before its own. */
    private static final int FIELDS = 4;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final String traceId;

    private final String spanId;

    private final String flags;

    private TraceParent(String traceId, String spanId, String flags) {
        this.traceId = traceId;
        this.spanId = spanId;
        this.flags = flags;
    }

    /**
     * The trace the request is part of: the one it stated, or one of its own where it stated nothing this can be read
     * from.
     *
     * @param traceparent what the request stated, which may be nothing
     * @return the trace to say everything about this request under
     */
    public static TraceParent of(String traceparent) {
        TraceParent stated = read(traceparent);
        return stated != null ? stated : mint();
    }

    /**
     * The trace stated in the header, or nothing where it states none that can be read.
     *
     * <p>
     * The first version of the header states these fields and nothing after them, so anything after them means the
     * header is not that version's and nothing is read from it. A version beyond the first may state more fields after
     * these, and those are left alone rather than refused: the first four are where every version states these.
     * </p>
     */
    private static TraceParent read(String traceparent) {
        if (traceparent == null) {
            return null;
        }
        String stated = traceparent.strip();
        String[] fields = stated.split("-");
        if (fields.length < FIELDS || !VERSION_SHAPE.matcher(fields[0]).matches() || NO_VERSION.equals(fields[0])) {
            return null;
        }
        if (FIRST_VERSION.equals(fields[0]) && !FIRST_VERSION_SHAPE.matcher(stated).matches()) {
            return null;
        }
        if (!TRACE_ID_SHAPE.matcher(fields[1]).matches() || NO_TRACE.equals(fields[1])) {
            return null;
        }
        if (!SPAN_ID_SHAPE.matcher(fields[2]).matches() || NO_SPAN.equals(fields[2])) {
            return null;
        }
        if (!FLAGS_SHAPE.matcher(fields[3]).matches()) {
            return null;
        }
        return new TraceParent(fields[1], fields[2], sampledBitOf(fields[3]));
    }

    /** A trace of this request's own, which nothing else knows and nothing is recording. */
    private static TraceParent mint() {
        return new TraceParent(identifier(16, NO_TRACE), identifier(8, NO_SPAN), NOT_SAMPLED_FLAG);
    }

    /**
     * An identifier of the given size that identifies something. Nothing but zeros identifies nothing, and what is read
     * is held to that, so what is made is held to it too rather than only being unlikely to break it.
     */
    private static String identifier(int bytes, String identifiesNothing) {
        String made;
        do {
            made = hex(bytes);
        } while (identifiesNothing.equals(made));
        return made;
    }

    /** Whether the trace is being recorded, which is all of the flags the schema accepts. */
    private static String sampledBitOf(String flags) {
        return (Integer.parseInt(flags, 16) & SAMPLED) == SAMPLED ? SAMPLED_FLAG : NOT_SAMPLED_FLAG;
    }

    private static String hex(int bytes) {
        byte[] made = new byte[bytes];
        RANDOM.nextBytes(made);
        StringBuilder written = new StringBuilder(bytes * 2);
        for (byte one : made) {
            written.append(String.format("%02x", one));
        }
        return written.toString();
    }

    public String traceId() {
        return traceId;
    }

    public String spanId() {
        return spanId;
    }

    public String flags() {
        return flags;
    }
}
