package com.podosoftware.cufit.web.controller.status;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import studio.one.platform.service.Repository;

@RestController
public class StatusPageConfigController {

    private static final DateTimeFormatter STARTED_AT_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                    .withZone(ZoneId.systemDefault());

    private final Repository repository;
    private final StatusPageBackgroundResolver backgroundResolver;

    public StatusPageConfigController(
            Repository repository,
            StatusPageBackgroundResolver backgroundResolver) {
        this.repository = repository;
        this.backgroundResolver = backgroundResolver;
    }

    @GetMapping(value = "/service-status-config.js", produces = "application/javascript")
    public String serviceStatusConfig() {
        Duration uptime = repository.getUptime();
        long uptimeSeconds = Math.max(0L, uptime.getSeconds());
        Instant startedAt = Instant.now().minusSeconds(uptimeSeconds);
        return "window.__SERVICE_STATUS__ = { backgroundImageUrl: "
                + toJsString(backgroundResolver.resolveBackgroundImageUrl())
                + ", startedAt: "
                + toJsString(STARTED_AT_FORMATTER.format(startedAt))
                + ", uptimeSeconds: "
                + uptimeSeconds
                + " };";
    }

    private static String toJsString(String value) {
        String escaped = value
                .replace("\\", "\\\\")
                .replace("'", "\\'")
                .replace("\r", "")
                .replace("\n", "\\n");
        return "'" + escaped + "'";
    }
}
