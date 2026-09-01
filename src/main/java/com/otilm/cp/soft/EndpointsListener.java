package com.otilm.cp.soft;

import com.otilm.api.model.core.connector.EndpointDto;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Component
public class EndpointsListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(EndpointsListener.class);

    private final List<EndpointDto> endpoints = new ArrayList<>();

    @EventListener
    public void handleContextRefresh(ContextRefreshedEvent event) {
        ApplicationContext applicationContext = event.getApplicationContext();

        RequestMappingHandlerMapping requestMappingHandlerMapping = applicationContext
                .getBean("requestMappingHandlerMapping", RequestMappingHandlerMapping.class);
        Map<RequestMappingInfo, HandlerMethod> map = requestMappingHandlerMapping
                .getHandlerMethods();

        Map<RequestMappingInfo, HandlerMethod> filteredMap = map.entrySet().stream()
                .filter(e -> !e.getKey().getMethodsCondition().getMethods().isEmpty())
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        filteredMap.forEach((key, value) -> {
            assert key.getPathPatternsCondition() != null;
            LOGGER.debug("{} {} {}", key.getMethodsCondition().getMethods(),
                    key.getPathPatternsCondition().getPatterns(),
                    value.getMethod().getName());

            EndpointDto endpoint = new EndpointDto();
            endpoint.setMethod(key.getMethodsCondition().getMethods().iterator().next().name());
            endpoint.setContext(key.getPathPatternsCondition().getPatterns().iterator().next().toString());
            endpoint.setName(value.getMethod().getName());
            endpoints.add(endpoint);
        });
    }

    public List<EndpointDto> getEndpoints(FunctionGroupCode functionGroup) {
        Pattern regex = Pattern.compile("^/v\\d+/" + functionGroup.getCode() + "/.*");

        return this.endpoints.stream()
                .filter(e -> regex.matcher(e.getContext()).matches())
                .toList();
    }
}