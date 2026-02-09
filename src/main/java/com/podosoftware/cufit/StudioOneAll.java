package com.podosoftware.cufit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.scheduling.annotation.EnableAsync;

import lombok.extern.slf4j.Slf4j;

@SpringBootApplication(exclude = { DataSourceAutoConfiguration.class })
@EnableCaching
@EnableAsync
@Slf4j
public class StudioOneAll {
    public static void main(String[] args) {
        SpringApplication.run(StudioOneAll.class, args);
    }
}
