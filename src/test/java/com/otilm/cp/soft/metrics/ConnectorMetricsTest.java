package com.otilm.cp.soft.metrics;

import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The count of the connector's own work is what an operator alerts on, so what it says has to survive the work failing,
 * and the names it says it under are the ones the interfaces state.
 */
class ConnectorMetricsTest {

    private PrometheusMeterRegistry registry;

    private ConnectorMetrics metrics;

    @BeforeEach
    void freshRegistry() {
        registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        metrics = new ConnectorMetrics(registry);
    }

    @Test
    void countsEveryEventFromTheStartSoAnUneventfulConnectorStillReports() {
        // given
        // when
        String exposition = registry.scrape();

        // then
        for (ConnectorEvent event : ConnectorEvent.values()) {
            assertTrue(exposition.contains(series(event, "success") + " 0.0"),
                    () -> "expected a count of no successful " + event.getCode() + ", got " + exposition);
            assertTrue(exposition.contains(series(event, "error") + " 0.0"),
                    () -> "expected a count of no failed " + event.getCode() + ", got " + exposition);
        }
    }

    @Test
    void countsWorkThatWasPerformed() {
        // given
        // when
        String produced = metrics.counting(ConnectorEvent.KEY_CREATED, () -> "a key");

        // then
        assertEquals("a key", produced);
        assertTrue(registry.scrape().contains(series(ConnectorEvent.KEY_CREATED, "success") + " 1.0"));
    }

    @Test
    void countsWorkThatFailedAndLetsTheFailureTravelOn() {
        // given
        IllegalStateException failure = new IllegalStateException("the token is not open");

        // when
        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> metrics.counting(ConnectorEvent.KEY_EXPORTED, () -> {
                    throw failure;
                }));

        // then
        assertEquals(failure, thrown);
        assertTrue(registry.scrape().contains(series(ConnectorEvent.KEY_EXPORTED, "error") + " 1.0"));
    }

    /**
     * A count is of the work, and work stated to fail with something checked can fail with it, so the failure has to
     * reach the caller as it is rather than wrapped in something the caller does not handle.
     */
    @Test
    void letsWorkFailWithWhatItSaysItFailsWith() {
        // given
        // when
        Exception thrown = assertThrows(InterruptedException.class,
                () -> metrics.counting(ConnectorEvent.DATA_SIGNED, () -> {
                    throw new InterruptedException("interrupted");
                }));

        // then
        assertEquals("interrupted", thrown.getMessage());
        assertTrue(registry.scrape().contains(series(ConnectorEvent.DATA_SIGNED, "error") + " 1.0"));
    }

    /**
     * Work the database went on to refuse did not happen, so it is not counted until the transaction it belongs to has
     * settled, and then it is counted as whatever the transaction did.
     */
    @Test
    void countsWorkInATransactionOnlyOnceThatTransactionHasSettled() {
        // given
        TransactionSynchronizationManager.initSynchronization();

        // when
        metrics.counting(ConnectorEvent.KEY_CREATED, () -> "a key");

        // then
        assertFalse(registry.scrape().contains(series(ConnectorEvent.KEY_CREATED, "success") + " 1.0"),
                "work is not counted while the transaction it belongs to is open");
    }

    @Test
    void countsWorkTheTransactionRolledBackAsHavingFailed() {
        // given
        TransactionSynchronizationManager.initSynchronization();
        metrics.counting(ConnectorEvent.KEY_CREATED, () -> "a key");

        // when
        settle(TransactionSynchronization.STATUS_ROLLED_BACK);

        // then
        assertTrue(registry.scrape().contains(series(ConnectorEvent.KEY_CREATED, "error") + " 1.0"));
    }

    @Test
    void countsWorkTheTransactionCommittedAsHavingWorked() {
        // given
        TransactionSynchronizationManager.initSynchronization();
        metrics.counting(ConnectorEvent.KEY_IMPORTED, () -> "a key");

        // when
        settle(TransactionSynchronization.STATUS_COMMITTED);

        // then
        assertTrue(registry.scrape().contains(series(ConnectorEvent.KEY_IMPORTED, "success") + " 1.0"));
    }

    /** Some work answers that it could not do part of what was asked instead of failing outright. */
    @Test
    void countsWorkThatAnsweredThatItDidNotWorkAsHavingFailed() {
        // given
        // when
        String produced = metrics.counting(ConnectorEvent.DATA_SIGNED, () -> "nothing signed", signed -> false);

        // then
        assertEquals("nothing signed", produced);
        assertTrue(registry.scrape().contains(series(ConnectorEvent.DATA_SIGNED, "error") + " 1.0"));
    }

    /** Whatever a test here left open, the next one starts outside a transaction. */
    @AfterEach
    void closeAnyTransaction() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    private static void settle(int status) {
        List
                .copyOf(TransactionSynchronizationManager.getSynchronizations())
                .forEach(synchronization -> synchronization.afterCompletion(status));
        TransactionSynchronizationManager.clearSynchronization();
    }

    private static String series(ConnectorEvent event, String outcome) {
        return "connector_events_total{event=\"" + event.getCode() + "\",outcome=\"" + outcome + "\"}";
    }
}
