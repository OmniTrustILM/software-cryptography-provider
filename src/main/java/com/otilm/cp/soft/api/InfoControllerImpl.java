package com.otilm.cp.soft.api;

import com.otilm.api.interfaces.connector.InfoController;
import com.otilm.api.model.client.connector.InfoResponse;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.cp.soft.EndpointsListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
public class InfoControllerImpl implements InfoController {
    private static final Logger logger = LoggerFactory.getLogger(InfoControllerImpl.class);

    @Autowired
    public void setEndpointsListener(EndpointsListener endpointsListener) {
        this.endpointsListener = endpointsListener;
    }

    private EndpointsListener endpointsListener;

    @Override
    public List<InfoResponse> listSupportedFunctions() {
        logger.debug("Listing the end points for Software Cryptography Provider");
        List<String> kinds = List.of("SOFT");
        List<InfoResponse> functions = new ArrayList<>();
        functions.add(new InfoResponse(
                kinds,
                FunctionGroupCode.CRYPTOGRAPHY_PROVIDER,
                endpointsListener.getEndpoints(FunctionGroupCode.CRYPTOGRAPHY_PROVIDER))
        );

        return functions;
    }
}