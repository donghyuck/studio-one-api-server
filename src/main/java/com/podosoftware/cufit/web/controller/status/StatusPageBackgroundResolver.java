package com.podosoftware.cufit.web.controller.status;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class StatusPageBackgroundResolver {

    private final String staticBackgroundImageUrl;
    private final boolean freeBackgroundEnabled;
    private final String freeBackgroundImageUrl;
    private final int probeTimeoutMillis;
    private final long cacheTtlMillis;

    private volatile long lastCheckedAt = 0L;
    private volatile String cachedUrl = "";

    public StatusPageBackgroundResolver(
            @Value("${app.status-page.background-image-url:}") String staticBackgroundImageUrl,
            @Value("${app.status-page.free-background.enabled:true}") boolean freeBackgroundEnabled,
            @Value("${app.status-page.free-background.image-url:https://picsum.photos/1920/1080}") String freeBackgroundImageUrl,
            @Value("${app.status-page.free-background.probe-timeout-ms:1500}") int probeTimeoutMillis,
            @Value("${app.status-page.free-background.cache-ttl-seconds:300}") long cacheTtlSeconds) {
        this.staticBackgroundImageUrl = normalize(staticBackgroundImageUrl);
        this.freeBackgroundEnabled = freeBackgroundEnabled;
        this.freeBackgroundImageUrl = normalize(freeBackgroundImageUrl);
        this.probeTimeoutMillis = Math.max(200, probeTimeoutMillis);
        this.cacheTtlMillis = TimeUnit.SECONDS.toMillis(Math.max(10, cacheTtlSeconds));
    }

    public String resolveBackgroundImageUrl() {
        if (StringUtils.hasText(staticBackgroundImageUrl)) {
            return staticBackgroundImageUrl;
        }
        if (!freeBackgroundEnabled || !StringUtils.hasText(freeBackgroundImageUrl)) {
            return "";
        }

        long now = System.currentTimeMillis();
        if (now - lastCheckedAt <= cacheTtlMillis) {
            return cachedUrl;
        }
        synchronized (this) {
            now = System.currentTimeMillis();
            if (now - lastCheckedAt <= cacheTtlMillis) {
                return cachedUrl;
            }
            cachedUrl = isReachable(freeBackgroundImageUrl) ? freeBackgroundImageUrl : "";
            lastCheckedAt = now;
            return cachedUrl;
        }
    }

    private boolean isReachable(String targetUrl) {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(targetUrl).openConnection();
            connection.setConnectTimeout(probeTimeoutMillis);
            connection.setReadTimeout(probeTimeoutMillis);
            connection.setRequestMethod("GET");
            connection.setInstanceFollowRedirects(true);
            connection.setRequestProperty("User-Agent", "StudioOneStatusPage/1.0");
            int statusCode = connection.getResponseCode();
            return statusCode >= 200 && statusCode < 400;
        } catch (Exception ignored) {
            return false;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}
