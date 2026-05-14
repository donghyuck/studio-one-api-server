package com.podosoftware.cufit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;

import lombok.extern.slf4j.Slf4j;

@SpringBootApplication(exclude = { DataSourceAutoConfiguration.class })
@EntityScan(basePackages = { "com.podosoftware.cufit", "studio.one" })
@EnableCaching
@EnableAsync
@Slf4j
public class StudioOneAll {
    public static void main(String[] args) {
        SpringApplication.run(StudioOneAll.class, args);
    }

    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher delegate) {
        return new DefaultAuthenticationEventPublisher(delegate);
    }
}
