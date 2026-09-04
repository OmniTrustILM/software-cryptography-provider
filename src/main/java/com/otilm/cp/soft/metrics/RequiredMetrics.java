package com.otilm.cp.soft.metrics;

import com.sun.management.OperatingSystemMXBean;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.prometheus.metrics.core.metrics.CounterWithCallback;
import io.prometheus.metrics.core.metrics.GaugeWithCallback;
import io.prometheus.metrics.core.metrics.Info;
import io.prometheus.metrics.model.registry.PrometheusRegistry;
import io.prometheus.metrics.model.snapshots.Unit;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Component;

/**
 * Publishes what the interfaces require to be known about the build and the running process.
 *
 * <p>
 * Only what is missing is added. A Spring application already publishes when its process started, under the very name
 * the interfaces ask for, so that reading is left where it is; the rest it either publishes under another name or does
 * not know at all.
 * </p>
 *
 * <p>
 * These are registered with the exposition library rather than through the metrics facade, because the facade derives
 * an exposed name from the name a meter is given: an {@code _info} suffix is dropped and a unit is appended, so the
 * same readings would reach a collector as {@code app_build} and {@code process_cpu_seconds_total_seconds_total}. The
 * names are fixed by the contract, so they are stated to the layer that publishes them unchanged.
 * </p>
 *
 * <p>
 * That layer will not carry an {@code _info} name as anything but an info metric, which is what the build is. A
 * collector reads it as the contract describes it, a gauge of 1, in the Prometheus text format; in OpenMetrics its
 * declared kind is {@code info} instead. The name and the reading are the same either way, and no name but the required
 * one can be published at all.
 * </p>
 */
@Component
public class RequiredMetrics {

    private static final Logger logger = LoggerFactory.getLogger(RequiredMetrics.class);

    /** Where a Linux process states its own memory. Nothing in the JVM reports resident memory. */
    private static final Path STATUS = Path.of("/proc/self/status");

    /** The line that states it, and the unit it is stated in. */
    private static final String RESIDENT = "VmRSS:";

    private static final long BYTES_PER_KIBIBYTE = 1024L;

    private static final String UNKNOWN = "unknown";

    private final BuildProperties build;

    public RequiredMetrics(PrometheusMeterRegistry registry, BuildProperties build) {
        this.build = build;
        register(registry.getPrometheusRegistry());
    }

    private void register(PrometheusRegistry registry) {
        Info
                .builder()
                .name(MetricContract.APP_BUILD_INFO)
                .help("The build this connector is running")
                .labelNames("version", "commit", "runtime")
                .register(registry)
                .setLabelValues(build.getVersion(), commit(build), runtime());

        CounterWithCallback
                .builder()
                .name(MetricContract.PROCESS_CPU_SECONDS_TOTAL)
                .help("Processor time this process has used")
                .unit(Unit.SECONDS)
                .callback(reading -> reading.call(processorSeconds()))
                .register(registry);

        GaugeWithCallback
                .builder()
                .name(MetricContract.PROCESS_RESIDENT_MEMORY_BYTES)
                .help("Memory this process is resident in")
                .unit(Unit.BYTES)
                .callback(reading -> reading.call(residentBytes(STATUS)))
                .register(registry);
    }

    /** The commit the build was made from, which is absent from a build made outside a working copy. */
    private static String commit(BuildProperties build) {
        String commit = build.get("commit");
        return commit == null ? UNKNOWN : commit;
    }

    /** The runtime this connector runs on, named the way the interfaces show it. */
    private static String runtime() {
        return "java-" + Runtime.version().feature();
    }

    /** Processor time, which the platform reports in nanoseconds where it reports it at all. */
    private static double processorSeconds() {
        if (ManagementFactory.getOperatingSystemMXBean() instanceof OperatingSystemMXBean operatingSystem) {
            long nanoseconds = operatingSystem.getProcessCpuTime();
            return nanoseconds < 0 ? 0 : nanoseconds / (double) TimeUnit.SECONDS.toNanos(1);
        }
        return 0;
    }

    /**
     * Resident memory, which only the operating system knows. It is read where the operating system publishes it, in
     * the kibibytes it publishes it in rather than in pages whose size varies, and reported as nothing elsewhere, since
     * a made-up figure would be worse than an absent one.
     */
    static double residentBytes(Path from) {
        try (Stream<String> status = Files.lines(from)) {
            return status
                    .filter(line -> line.startsWith(RESIDENT))
                    .mapToDouble(RequiredMetrics::kibibytes)
                    .findFirst()
                    .orElse(0);
        } catch (IOException | RuntimeException e) {
            logger.debug("This system does not publish the memory a process is resident in", e);
            return 0;
        }
    }

    private static double kibibytes(String line) {
        return Long.parseLong(line.split("\\s+")[1]) * (double) BYTES_PER_KIBIBYTE;
    }
}
