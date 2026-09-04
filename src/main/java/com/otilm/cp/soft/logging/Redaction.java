package com.otilm.cp.soft.logging;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Takes out of a log line what must not be written down.
 *
 * <p>
 * This connector's own lines say what happened and name the objects it happened to, never the material or the code that
 * opens it. What arrives here comes from everything else that logs: the key technology, the persistence layer, the
 * framework, and the message of a failure any of them raised, which can quote what it was given.
 * </p>
 *
 * <p>
 * A value is taken out by the name it was written under, and a key by the shape it is written in. A value is taken to
 * the end of what it could be rather than to the first space, since a passphrase may contain one; it stops at the
 * punctuation that separates one field from the next, so what a line says about the objects it names survives. Taking
 * out too much of a line is the safer way to be wrong.
 * </p>
 *
 * <p>
 * What this cannot do is follow a value onto the next line: a secret written with a line break inside it leaves its
 * remainder in place, since nothing distinguishes that remainder from the next thing the line had to say.
 * </p>
 */
public final class Redaction {

    /**
     * What this connector, the platform and the libraries under them call a secret. A name matches as part of a longer
     * one, so that {@code oldPassword} is taken out along with {@code password} — which is also why a word as common as
     * {@code code} is not among them: it would take out an {@code errorCode} or a {@code statusCode} and leave a line
     * saying nothing about what went wrong.
     */
    private static final String NAMES = "passphrase|password|secret|credential|token|token_?code|activation_?code"
            + "|access_?token|refresh_?token|client_?secret|authorization|private_?key"
            + "|encrypted_?private_?key_?info|keystore";

    /** A name is written quoted where it is part of a document and bare where it is part of a sentence. */
    private static final String QUOTED = "[\"']?";

    private static final String ASSIGNED = "\\s*[:=]\\s*";

    /** Where one field ends and the next begins, which is as far as a value is taken. */
    private static final String TO_THE_END_OF_THE_VALUE = "[^\\n,;}\\]]+";

    private static final String TAKEN_OUT = "$1[redacted]";

    /**
     * The quoted forms are tried before the bare one, which would otherwise stop at the opening quote and leave the
     * closing one behind with the value still in place. An object stated in place of a value is taken whole.
     */
    private static final List<Pattern> BY_NAME = List
            .of(writtenAs("\\{[^{}]*\\}"), writtenAs("\"[^\"]*\""), writtenAs("'[^']*'"),
                    writtenAs(TO_THE_END_OF_THE_VALUE), Pattern.compile("(?i)((?:bearer|basic)\\s+)\\S+"));

    /** A key written out in full, which is what an envelope or a keystore dump looks like. */
    private static final Pattern KEY_BEGINS = Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----");

    private static final String KEY_ENDS = "-----";

    private static final String END_MARKER = "-----END ";

    private static final String KEY_TAKEN_OUT = "[redacted private key]";

    private Redaction() {
    }

    /**
     * The line as it may be written down.
     *
     * @param line what was said, which may be nothing
     * @return the same line with what must not be written down taken out
     */
    public static String of(String line) {
        if (line == null) {
            return null;
        }
        String redacted = withoutKeys(line);
        for (Pattern named : BY_NAME) {
            redacted = named.matcher(redacted).replaceAll(TAKEN_OUT);
        }
        return redacted;
    }

    /**
     * The line without any key written out in it. The end of a key is found by looking for it rather than by matching
     * across it: a line carrying opening markers and no closing one would otherwise be searched once for every marker
     * it carries, which on the thread writing the line is time the request waits for.
     */
    private static String withoutKeys(String line) {
        Matcher begins = KEY_BEGINS.matcher(line);
        if (!begins.find()) {
            return line;
        }
        StringBuilder without = new StringBuilder(line.length());
        int taken = 0;
        do {
            if (begins.start() < taken) {
                continue;
            }
            without.append(line, taken, begins.start()).append(KEY_TAKEN_OUT);
            taken = endOfKey(line, begins.end());
        } while (begins.find());
        return without.append(line, Math.min(taken, line.length()), line.length()).toString();
    }

    /**
     * Where the key ends, which is after its closing marker. A key that was cut off has no closing marker, and what is
     * left of the line is the key, so the line ends there.
     */
    private static int endOfKey(String line, int afterTheOpeningMarker) {
        int ends = line.indexOf(END_MARKER, afterTheOpeningMarker);
        if (ends < 0) {
            return line.length();
        }
        int after = line.indexOf(KEY_ENDS, ends + END_MARKER.length());
        return after < 0 ? line.length() : after + KEY_ENDS.length();
    }

    /** A secret written under any of the names, however that name and its value are punctuated. */
    private static Pattern writtenAs(String value) {
        return Pattern.compile("(?i)(" + QUOTED + "(?:" + NAMES + ")" + QUOTED + ASSIGNED + ")" + value);
    }
}
