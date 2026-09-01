package com.otilm.cp.soft.service.impl;

import com.otilm.api.model.common.HealthDto;
import com.otilm.api.model.common.HealthStatus;
import com.otilm.cp.soft.service.HealthService;
import org.springframework.stereotype.Service;

@Service
public class HealthServiceImpl implements HealthService {

    @Override
    public HealthDto checkHealth() {
        HealthDto health = new HealthDto();
        // Only the overall status is reported; the connector has no sub-components to check.
        health.setStatus(HealthStatus.OK);
        return health;
    }

}
