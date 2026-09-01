package com.otilm.cp.soft.api;

import com.otilm.api.interfaces.connector.HealthController;
import com.otilm.api.model.common.HealthDto;
import com.otilm.cp.soft.service.HealthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthControllerImpl implements HealthController {

    @Autowired
    public void setHealthService(HealthService healthService) {
        this.healthService = healthService;
    }

    HealthService healthService;

    @Override
    public HealthDto checkHealth() {
        return healthService.checkHealth();
    }
}
