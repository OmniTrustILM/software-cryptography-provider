package com.otilm.cp.soft.api.v2;

import com.otilm.api.interfaces.connector.common.v2.MetricsController;
import com.otilm.cp.soft.exception.MetricsUnavailableException;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.prometheus.metrics.expositionformats.OpenMetricsTextFormatWriter;
import io.prometheus.metrics.expositionformats.PrometheusTextFormatWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves this connector's metrics for a collector to read.
 *
 * <p>
 * Both exposition formats the interfaces describe are served, and OpenMetrics is the preferred one, so it is what a
 * collector that states no preference is given. A collector that asks for something neither format satisfies is given
 * the preferred one as well: one misconfigured to ask for the wrong thing should still be able to read the metrics,
 * which is worth more here than being told its request was unacceptable.
 * </p>
 *
 * <p>
 * The content type is set on the response rather than negotiated by the framework, so that the format chosen here is
 * the format that is both written and declared, and only once there is something to declare. The request and the
 * response are held rather than taken as arguments because the contract fixes what this operation is called with, which
 * is nothing.
 * </p>
 */
@RestController
public class MetricsV2ControllerImpl implements MetricsController {

    /** The parameter that names an exposition format, which both of the ones served carry. */
    private static final String VERSION = "version";

    private static final MediaType OPEN_METRICS = MediaType.parseMediaType(OpenMetricsTextFormatWriter.CONTENT_TYPE);

    private static final MediaType PROMETHEUS_TEXT = MediaType.parseMediaType(PrometheusTextFormatWriter.CONTENT_TYPE);

    private final PrometheusMeterRegistry registry;

    private final HttpServletRequest request;

    private final HttpServletResponse response;

    public MetricsV2ControllerImpl(PrometheusMeterRegistry registry, HttpServletRequest request,
            HttpServletResponse response) {
        this.registry = registry;
        this.request = request;
        this.response = response;
    }

    @Override
    public String getMetrics() {
        String format = negotiated(request.getHeader(HttpHeaders.ACCEPT));
        String exposition = scrape(format);
        // Readings are written one after another into a single document, and a reading that cannot be written
        // abandons the document rather than the reading. There is always something to expose, so nothing exposed
        // means the document was abandoned.
        if (exposition.isEmpty()) {
            throw new MetricsUnavailableException("The metrics of this connector could not be written as " + format);
        }
        // Declared only once there is something to declare: a failure answers as a problem document, and the
        // framework gives that its own content type.
        response.setContentType(format);
        return exposition;
    }

    private String scrape(String format) {
        try {
            return registry.scrape(format);
        } catch (RuntimeException e) {
            throw new MetricsUnavailableException("The metrics of this connector could not be read", e);
        }
    }

    /**
     * The format to answer in: the first one the collector asks for that this connector serves, and the preferred one
     * where it asks for nothing in particular or for nothing this connector has.
     */
    private static String negotiated(String accept) {
        for (MediaType wanted : preferences(accept)) {
            if (wanted.isWildcardType()) {
                break;
            }
            if (satisfies(wanted, OPEN_METRICS)) {
                return OpenMetricsTextFormatWriter.CONTENT_TYPE;
            }
            if (satisfies(wanted, PROMETHEUS_TEXT)) {
                return PrometheusTextFormatWriter.CONTENT_TYPE;
            }
        }
        return OpenMetricsTextFormatWriter.CONTENT_TYPE;
    }

    /**
     * Whether one of the formats this connector serves is what the collector asked for. A version it named has to be
     * the version served, since that is what names the exposition format; anything else it named is not matched, a
     * charset least of all, as both formats are written in UTF-8 whatever is asked for.
     */
    private static boolean satisfies(MediaType wanted, MediaType offered) {
        if (!wanted.isCompatibleWith(offered)) {
            return false;
        }
        String version = wanted.getParameter(VERSION);
        return version == null || version.equals(offered.getParameter(VERSION));
    }

    /**
     * What the collector asked for, most wanted first. Equal wants keep the order they were stated in, since the sort
     * is stable, and a header that cannot be read states no preference.
     */
    private static List<MediaType> preferences(String accept) {
        try {
            List<MediaType> accepted = new ArrayList<>(MediaType.parseMediaTypes(accept));
            accepted.sort(Comparator.comparingDouble(MediaType::getQualityValue).reversed());
            return accepted;
        } catch (InvalidMediaTypeException e) {
            return List.of();
        }
    }
}
