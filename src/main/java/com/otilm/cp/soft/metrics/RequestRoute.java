package com.otilm.cp.soft.metrics;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.servlet.HandlerMapping;

/**
 * The route a request matched, which is what a metric is labelled by.
 *
 * <p>
 * A label is the route rather than the path that was asked for, so that a path carrying a token or a key identifier
 * cannot multiply the series without limit. A request that matched no route is labelled as such for the same reason.
 * </p>
 */
final class RequestRoute {

    private static final String UNMATCHED = "unmatched";

    private RequestRoute() {
    }

    static String of(HttpServletRequest request) {
        Object matched = request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
        return matched == null ? UNMATCHED : matched.toString();
    }
}
