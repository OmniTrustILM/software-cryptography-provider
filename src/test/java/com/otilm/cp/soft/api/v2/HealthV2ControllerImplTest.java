package com.otilm.cp.soft.api.v2;

import com.otilm.api.model.client.connector.v2.HealthStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.availability.AvailabilityChangeEvent;
import org.springframework.boot.availability.ReadinessState;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The platform reads this connector's state here, and an orchestrator decides on the status code, so what the report
 * says and what it is answered with have to agree. Liveness and readiness are reported on every request.
 */
@SpringBootTest
@AutoConfigureMockMvc
class HealthV2ControllerImplTest {

    private static final String HEALTH = "/v2/health";

    private MockMvc mockMvc;

    private ApplicationContext context;

    @Autowired
    void setMockMvc(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    @Autowired
    void setContext(ApplicationContext context) {
        this.context = context;
    }

    /** Whatever a test here changed, the application is left accepting traffic for the tests that follow. */
    @AfterEach
    void acceptTrafficAgain() {
        AvailabilityChangeEvent.publish(context, ReadinessState.ACCEPTING_TRAFFIC);
    }

    @Test
    void reportsTheConnectorAndTheComponentsTheContractRequires() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(get(HEALTH))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(HealthStatus.UP.getCode()))
                .andExpect(jsonPath("$.components.liveness.status").value(HealthStatus.UP.getCode()))
                .andExpect(jsonPath("$.components.readiness.status").value(HealthStatus.UP.getCode()))
                .andExpect(jsonPath("$.components.database.status").value(HealthStatus.UP.getCode()));
    }

    @Test
    void reportsEachProbeOnItsOwn() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(get(HEALTH + "/liveness"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(HealthStatus.UP.getCode()))
                .andExpect(jsonPath("$.components.liveness.status").value(HealthStatus.UP.getCode()));
        mockMvc
                .perform(get(HEALTH + "/readiness"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(HealthStatus.UP.getCode()))
                .andExpect(jsonPath("$.components.readiness.status").value(HealthStatus.UP.getCode()));
    }

    /**
     * An application that has stopped accepting traffic must be answered with a code the orchestrator routes away from,
     * not only with a body saying so.
     */
    @Test
    void answersUnavailableWhenTheConnectorStopsAcceptingTraffic() throws Exception {
        // given
        AvailabilityChangeEvent.publish(context, ReadinessState.REFUSING_TRAFFIC);

        // when
        // then
        mockMvc
                .perform(get(HEALTH + "/readiness"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value(HealthStatus.OUT_OF_SERVICE.getCode()));
        mockMvc
                .perform(get(HEALTH))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value(HealthStatus.OUT_OF_SERVICE.getCode()))
                .andExpect(jsonPath("$.components.liveness.status").value(HealthStatus.UP.getCode()));
    }

    /** Liveness is about the application itself, so it stays up while the connector is refusing traffic. */
    @Test
    void keepsReportingLivenessWhileRefusingTraffic() throws Exception {
        // given
        AvailabilityChangeEvent.publish(context, ReadinessState.REFUSING_TRAFFIC);

        // when
        // then
        mockMvc
                .perform(get(HEALTH + "/liveness"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(HealthStatus.UP.getCode()));
    }

    /**
     * A health indicator's details can name a host or a connection string, and this endpoint answers without
     * credentials, so only the status of each component is published.
     */
    @Test
    void publishesNoDetailsOfItsComponents() throws Exception {
        // given
        // when
        // then
        mockMvc
                .perform(get(HEALTH))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.components.database.details").doesNotExist());
    }
}
