package com.otilm.cp.soft.metrics;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.AsyncHandlerInterceptor;

/**
 * Reports how many requests this connector is serving right now, by route.
 *
 * <p>
 * The reading is taken here rather than in a servlet filter because the route a request matched is only known once a
 * handler has been chosen, and the interfaces require the reading to be labelled by that route. The route is kept on
 * the request so that what is given back is what was taken, whatever the request goes on to do.
 * </p>
 *
 * <p>
 * A request handed off to be finished later is given back at the hand-off and taken again when it resumes, since the
 * framework chooses its handler afresh then. Nothing here is handed off today, and a reading that counted one such
 * request forever would be worse than one that is simply never reached.
 * </p>
 */
@Component
public class InFlightRequests implements AsyncHandlerInterceptor {

    private static final String ROUTE = InFlightRequests.class.getName() + ".route";

    private final MeterRegistry registry;

    private final Map<String, AtomicInteger> serving = new ConcurrentHashMap<>();

    public InFlightRequests(MeterRegistry registry) {
        this.registry = registry;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String route = RequestRoute.of(request);
        request.setAttribute(ROUTE, route);
        gauged(route).incrementAndGet();
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler,
            Exception failure) {
        served(request);
    }

    @Override
    public void afterConcurrentHandlingStarted(HttpServletRequest request, HttpServletResponse response,
            Object handler) {
        served(request);
    }

    private void served(HttpServletRequest request) {
        Object route = request.getAttribute(ROUTE);
        if (route != null) {
            gauged(route.toString()).decrementAndGet();
        }
    }

    private AtomicInteger gauged(String route) {
        return serving.computeIfAbsent(route, labelled -> {
            AtomicInteger count = new AtomicInteger();
            Gauge
                    .builder(MetricContract.HTTP_SERVER_IN_FLIGHT_REQUESTS, count, AtomicInteger::get)
                    .description("Requests this connector is serving right now")
                    .tag("route", labelled)
                    .register(registry);
            return count;
        });
    }
}
