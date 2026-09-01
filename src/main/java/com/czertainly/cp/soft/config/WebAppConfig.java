package com.czertainly.cp.soft.config;

import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import org.springframework.context.annotation.Configuration;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebAppConfig implements WebMvcConfigurer {
    @Override
    public void addFormatters(FormatterRegistry registry) {
        // The source and target types are passed explicitly. The single-argument overload
        // reads them from the Converter's generic signature, which a lambda does not carry,
        // and Spring then fails to build the conversion service.
        registry.addConverter(String.class, KeyAlgorithm.class, KeyAlgorithm::findByCode);
    }
}
