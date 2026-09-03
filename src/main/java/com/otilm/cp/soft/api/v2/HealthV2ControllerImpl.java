package com.otilm.cp.soft.api.v2;

import com.otilm.api.interfaces.connector.common.v2.HealthController;
import com.otilm.api.model.client.connector.v2.HealthInfo;
import com.otilm.api.model.client.connector.v2.HealthInfoComponent;
import com.otilm.api.model.client.connector.v2.HealthStatus;
import jakarta.servlet.http.HttpServletResponse;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.actuate.health.HealthComponent;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.health.Status;
import org.springframework.boot.availability.ApplicationAvailability;
import org.springframework.boot.availability.LivenessState;
import org.springframework.boot.availability.ReadinessState;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Reports whether this connector is running, and whether it can serve requests.
 *
 * <p>
 * Liveness and readiness are the application's own availability state, which a Spring application always keeps, rather
 * than the health groups the management endpoints can be configured to publish: both must be reported on every request
 * regardless of how this connector's own endpoints are exposed. Readiness also weighs the database, since the keystores
 * live there and nothing can be served without it.
 * </p>
 *
 * <p>
 * Only the status of each component is published. What a health indicator puts in its details can name a host or a
 * connection string, and this endpoint answers without credentials.
 * </p>
 *
 * <p>
 * Anything but a connector that can serve is answered with 503, since an orchestrator acts on the status code. The
 * declared return type carries the report itself, so the code is set on the response.
 * </p>
 */
@RestController
public class HealthV2ControllerImpl implements HealthController {

    private static final String LIVENESS = "liveness";

    private static final String READINESS = "readiness";

    private static final String DATABASE = "database";

    /** The name the application's own health report gives the datastore the keystores live in. */
    private static final String DATABASE_INDICATOR = "db";

    private final ApplicationAvailability availability;

    private final HealthEndpoint healthEndpoint;

    private final HttpServletResponse response;

    public HealthV2ControllerImpl(ApplicationAvailability availability, HealthEndpoint healthEndpoint,
            HttpServletResponse response) {
        this.availability = availability;
        this.healthEndpoint = healthEndpoint;
        this.response = response;
    }

    @Override
    public HealthInfo checkHealth() {
        HealthStatus liveness = liveness();
        HealthStatus readiness = readiness();
        HealthStatus database = database();

        Map<String, HealthInfoComponent> components = new LinkedHashMap<>();
        components.put(LIVENESS, component(liveness));
        components.put(READINESS, component(readiness));
        components.put(DATABASE, component(database));

        HealthInfo info = new HealthInfo();
        info.setStatus(worstOf(liveness, worstOf(readiness, database)));
        info.setComponents(components);
        return answer(info);
    }

    @Override
    public HealthInfo checkHealthLiveness() {
        return probe(LIVENESS, liveness());
    }

    @Override
    public HealthInfo checkHealthReadiness() {
        return probe(READINESS, readiness());
    }

    /** Whether the application is running. A broken application cannot recover, so it is replaced rather than kept. */
    private HealthStatus liveness() {
        return availability.getLivenessState() == LivenessState.CORRECT ? HealthStatus.UP : HealthStatus.DOWN;
    }

    /** Whether requests can be served, which needs both the application and the datastore behind it. */
    private HealthStatus readiness() {
        if (availability.getReadinessState() != ReadinessState.ACCEPTING_TRAFFIC) {
            return HealthStatus.OUT_OF_SERVICE;
        }
        return database();
    }

    private HealthStatus database() {
        return statusOf(healthEndpoint.healthForPath(DATABASE_INDICATOR));
    }

    /** One probe reported on its own, so an orchestrator asking only about it reads the same status either way. */
    private HealthInfo probe(String name, HealthStatus status) {
        HealthInfo info = new HealthInfo();
        info.setStatus(status);
        info.setComponents(Map.of(name, component(status)));
        return answer(info);
    }

    private static HealthInfoComponent component(HealthStatus status) {
        HealthInfoComponent component = new HealthInfoComponent();
        component.setStatus(status);
        return component;
    }

    /**
     * The reported status of one part of the application. A part this application does not report on is unknown rather
     * than well, since answering that it is up would state something this connector has not checked.
     */
    private static HealthStatus statusOf(HealthComponent health) {
        if (health == null) {
            return HealthStatus.UNKNOWN;
        }
        Status status = health.getStatus();
        if (Status.UP.equals(status)) {
            return HealthStatus.UP;
        }
        if (Status.DOWN.equals(status)) {
            return HealthStatus.DOWN;
        }
        if (Status.OUT_OF_SERVICE.equals(status)) {
            return HealthStatus.OUT_OF_SERVICE;
        }
        return HealthStatus.UNKNOWN;
    }

    /** The status a caller has to act on when two parts disagree, which is whichever of them is the more serious. */
    private static HealthStatus worstOf(HealthStatus one, HealthStatus other) {
        return severity(one) <= severity(other) ? one : other;
    }

    private static int severity(HealthStatus status) {
        return switch (status) {
            case DOWN -> 0;
            case OUT_OF_SERVICE -> 1;
            case UNKNOWN -> 2;
            case DEGRADED -> 3;
            case UP -> 4;
        };
    }

    private HealthInfo answer(HealthInfo info) {
        if (info.getStatus() != HealthStatus.UP && info.getStatus() != HealthStatus.DEGRADED) {
            response.setStatus(HttpStatus.SERVICE_UNAVAILABLE.value());
        }
        return info;
    }
}
