package com.otilm.cp.soft.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.function.Predicate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Counts the work this connector performs and whether performing it worked.
 *
 * <p>
 * The interfaces name one counter for a connector's own unit of work, labelled by the event and its outcome. What is
 * worth counting here is the work a caller asks for: the keys that come into a token and leave it, and the
 * cryptographic operations performed with them. A rising failure rate on one of those is what an operator acts on, and
 * the key lifecycle is what an auditor asks about.
 * </p>
 *
 * <p>
 * A count is taken where the work is performed, so a caller on either generation of the interfaces is counted once and
 * only once. What it records is the work, not the answer the caller received: a request turned away before any work
 * began is not counted here, since the count of requests already reports it under the status it was turned away with.
 * </p>
 *
 * <p>
 * Work inside a transaction is counted once that transaction has settled, since work the database went on to refuse did
 * not happen. Work that produced an answer saying it failed is counted as having failed, whatever it returned.
 * </p>
 *
 * <p>
 * Every event this connector can report is counted from the moment it starts, so a rate over a count that has not
 * happened yet reads as none rather than as nothing at all.
 * </p>
 */
@Component
public class ConnectorMetrics {

    /** The outcome names the interfaces state for this counter. */
    private static final String SUCCESS = "success";

    private static final String ERROR = "error";

    private final MeterRegistry registry;

    public ConnectorMetrics(MeterRegistry registry) {
        this.registry = registry;
        for (ConnectorEvent event : ConnectorEvent.values()) {
            counter(event, SUCCESS);
            counter(event, ERROR);
        }
    }

    /**
     * Performs the given work and counts whichever way it goes. Anything the work throws is left to travel on: the
     * count records what happened, and how the caller is answered is decided elsewhere.
     *
     * @param event the event the work performs
     * @param work the work itself
     * @param <T> what the work produces
     * @param <E> what the work can fail with
     * @return whatever the work produced
     * @throws E whatever the work failed with
     */
    public <T, E extends Exception> T counting(ConnectorEvent event, Work<T, E> work) throws E {
        return counting(event, work, produced -> true);
    }

    /**
     * Performs the given work and counts whichever way it goes, asking the given test whether what the work produced
     * says it worked. Some work answers that it could not do part of what was asked instead of failing outright.
     *
     * @param event the event the work performs
     * @param work the work itself
     * @param worked whether what the work produced says it worked
     * @param <T> what the work produces
     * @param <E> what the work can fail with
     * @return whatever the work produced
     * @throws E whatever the work failed with
     */
    public <T, E extends Exception> T counting(ConnectorEvent event, Work<T, E> work, Predicate<T> worked) throws E {
        boolean performed = false;
        try {
            T produced = work.perform();
            performed = worked.test(produced);
            return produced;
        } finally {
            countOnceSettled(event, performed);
        }
    }

    /**
     * Counts the work, waiting for the transaction it belongs to where it has one. Work that failed is counted at once:
     * it registers nothing to wait for, and the rollback that follows would otherwise count it twice.
     */
    private void countOnceSettled(ConnectorEvent event, boolean performed) {
        if (performed && TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCompletion(int status) {
                    count(event, status == STATUS_COMMITTED ? SUCCESS : ERROR);
                }
            });
            return;
        }
        count(event, performed ? SUCCESS : ERROR);
    }

    private void count(ConnectorEvent event, String outcome) {
        counter(event, outcome).increment();
    }

    private Counter counter(ConnectorEvent event, String outcome) {
        return Counter
                .builder(MetricContract.CONNECTOR_EVENTS_TOTAL)
                .description("Work this connector was asked to perform")
                .tag("event", event.getCode())
                .tag("outcome", outcome)
                .register(registry);
    }

    /**
     * A piece of work that is counted.
     *
     * @param <T> what the work produces
     * @param <E> what the work can fail with
     */
    @FunctionalInterface
    public interface Work<T, E extends Exception> {

        /**
         * @return what the work produced
         * @throws E where the work could not be performed
         */
        T perform() throws E;
    }
}
