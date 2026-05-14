package com.podosoftware.cufit.web.config;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
@Order(Ordered.LOWEST_PRECEDENCE - 10)
public class LegacyApiCompatibilityFilter extends OncePerRequestFilter {

    private static final Pattern DOWNLOAD_FILE_PATTERN = Pattern.compile("^/download/files/(\\d+)(?:/.*)?$");
    private static final Pattern DOWNLOAD_AVATAR_PATTERN = Pattern
            .compile("^/download/avatars/([^/]+)/thumbnail(?:/.*)?$");
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {
    };

    private final ObjectMapper objectMapper;

    public LegacyApiCompatibilityFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return !uri.startsWith("/data/")
                && !uri.startsWith("/download/")
                && !uri.startsWith("/streaming/");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        LegacyRoute route = route(request);
        if (route == null) {
            filterChain.doFilter(request, response);
            return;
        }
        if (route.requiresAuthentication() && !isAuthenticated()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        ContentCachingResponseWrapper wrapped = new ContentCachingResponseWrapper(response);
        RequestDispatcher dispatcher = request.getRequestDispatcher(route.path());
        dispatcher.forward(new LegacyRequestWrapper(request, route.method(), route.path()), wrapped);

        if (!route.convertBody()) {
            wrapped.copyBodyToResponse();
            return;
        }
        writeLegacyBody(route, wrapped, response);
    }

    private LegacyRoute route(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String method = request.getMethod();

        if ("/data/accounts/signin.json".equals(uri)) {
            return new LegacyRoute("/api/auth/login", method, false, true);
        }
        if ("/data/accounts/me".equals(uri)) {
            return new LegacyRoute("/api/self", method, true, true);
        }
        if ("/data/accounts/me/password".equals(uri)) {
            return new LegacyRoute("/api/self/password", method, true, true);
        }
        if ("/data/accounts/me/avatar".equals(uri)) {
            return new LegacyRoute("/api/me/avatar", method, true, true);
        }

        Matcher avatar = DOWNLOAD_AVATAR_PATTERN.matcher(uri);
        if (avatar.matches()) {
            return new LegacyRoute("/api/profile/" + avatar.group(1) + "/avatar", "GET", false, false);
        }
        Matcher file = DOWNLOAD_FILE_PATTERN.matcher(uri);
        if (file.matches()) {
            return new LegacyRoute("/api/attachments/" + file.group(1) + "/download", "GET", true, false);
        }

        String path = null;
        if (uri.startsWith("/data/secure/mgmt/security/users")) {
            path = "/api/mgmt/users" + uri.substring("/data/secure/mgmt/security/users".length());
        } else if (uri.startsWith("/data/secure/mgmt/security/groups")) {
            path = "/api/mgmt/groups" + uri.substring("/data/secure/mgmt/security/groups".length());
        } else if (uri.startsWith("/data/secure/mgmt/security/roles")) {
            path = "/api/mgmt/roles" + uri.substring("/data/secure/mgmt/security/roles".length());
        } else if (uri.startsWith("/data/secure/mgmt/resources/files")) {
            path = "/api/mgmt/attachments" + uri.substring("/data/secure/mgmt/resources/files".length());
        } else if (uri.startsWith("/data/secure/mgmt/resources/templates")) {
            path = "/api/mgmt/templates" + uri.substring("/data/secure/mgmt/resources/templates".length());
        } else if (uri.startsWith("/data/secure/mgmt/resources/objectstorage")) {
            path = "/api/mgmt/objectstorage/providers"
                    + uri.substring("/data/secure/mgmt/resources/objectstorage".length());
        } else if (uri.startsWith("/data/secure/mgmt/services/mail")) {
            path = "/api/mgmt/mail" + uri.substring("/data/secure/mgmt/services/mail".length());
        } else if (uri.startsWith("/data/resources")) {
            path = "/api/attachments/objects" + uri.substring("/data/resources".length());
        }
        if (path == null) {
            return null;
        }
        RouteAction action = normalize(path, method);
        return new LegacyRoute(action.path(), action.method(), true, true);
    }

    private RouteAction normalize(String path, String method) {
        String normalizedPath = path;
        String normalizedMethod = method;
        if (normalizedPath.endsWith(":search")) {
            normalizedPath = normalizedPath.substring(0, normalizedPath.length() - ":search".length());
            normalizedMethod = "GET";
        } else if (normalizedPath.endsWith(":find")) {
            normalizedPath = normalizedPath.substring(0, normalizedPath.length() - ":find".length()) + "/find";
            normalizedMethod = "GET";
        } else if (normalizedPath.endsWith(":delete")) {
            normalizedPath = normalizedPath.substring(0, normalizedPath.length() - ":delete".length());
            normalizedMethod = "DELETE";
        }
        if (normalizedPath.matches("^/api/mgmt/templates/\\d+:test$")) {
            normalizedPath = normalizedPath.replace(":test", "/render/body");
        }
        if ("POST".equalsIgnoreCase(normalizedMethod) && normalizedPath.endsWith("/0")) {
            normalizedPath = normalizedPath.substring(0, normalizedPath.length() - 2);
        } else if ("POST".equalsIgnoreCase(normalizedMethod) && normalizedPath.matches("^.*/\\d+$")) {
            normalizedMethod = "PUT";
        }
        normalizedPath = normalizedPath.replace("/api/mgmt/attachments/0/upload", "/api/mgmt/attachments");
        normalizedPath = normalizedPath.replaceAll("^/api/mgmt/attachments/(\\d+)/upload$", "/api/mgmt/attachments/$1");
        return new RouteAction(normalizedPath, normalizedMethod);
    }

    private void writeLegacyBody(
            LegacyRoute route,
            ContentCachingResponseWrapper wrapped,
            HttpServletResponse response) throws IOException {
        byte[] body = wrapped.getContentAsByteArray();
        if (body.length == 0 || !isJson(wrapped.getContentType())) {
            wrapped.copyBodyToResponse();
            return;
        }

        Map<String, Object> root = objectMapper.readValue(body, MAP_TYPE);
        Object legacyBody = toLegacyBody(route, root);
        byte[] converted = objectMapper.writeValueAsBytes(legacyBody);

        response.setStatus(wrapped.getStatus());
        copyHeaders(wrapped, response);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setContentLength(converted.length);
        response.getOutputStream().write(converted);
    }

    @SuppressWarnings("unchecked")
    private Object toLegacyBody(LegacyRoute route, Map<String, Object> root) {
        Object data = root.containsKey("data") ? root.get("data") : root;
        if ("/api/auth/login".equals(route.path()) && data instanceof Map<?, ?> map) {
            Object token = map.get("accessToken");
            if (token != null) {
                Map<String, Object> legacy = new LinkedHashMap<>();
                legacy.put("jwtToken", token);
                return legacy;
            }
        }
        if (data instanceof Map<?, ?> map && map.containsKey("content") && map.containsKey("totalElements")) {
            Map<String, Object> legacy = new LinkedHashMap<>();
            legacy.put("items", map.get("content"));
            legacy.put("content", map.get("content"));
            legacy.put("totalCount", map.get("totalElements"));
            legacy.put("totalElements", map.get("totalElements"));
            legacy.put("page", map.get("number"));
            legacy.put("size", map.get("size"));
            legacy.put("totalPages", map.get("totalPages"));
            return legacy;
        }
        return data;
    }

    private boolean isJson(String contentType) {
        return contentType != null && contentType.toLowerCase().contains("json");
    }

    private void copyHeaders(ContentCachingResponseWrapper source, HttpServletResponse target) {
        for (String header : source.getHeaderNames()) {
            if (!HttpHeaders.CONTENT_LENGTH.equalsIgnoreCase(header)) {
                target.setHeader(header, source.getHeader(header));
            }
        }
    }

    private boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null
                && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken);
    }

    private record LegacyRoute(String path, String method, boolean requiresAuthentication, boolean convertBody) {
    }

    private record RouteAction(String path, String method) {
    }

    private static class LegacyRequestWrapper extends HttpServletRequestWrapper {
        private final String method;
        private final String path;

        LegacyRequestWrapper(HttpServletRequest request, String method, String path) {
            super(request);
            this.method = method;
            this.path = path;
        }

        @Override
        public String getMethod() {
            return method;
        }

        @Override
        public String getRequestURI() {
            return path;
        }

        @Override
        public StringBuffer getRequestURL() {
            HttpServletRequest request = (HttpServletRequest) getRequest();
            return new StringBuffer(request.getScheme())
                    .append("://")
                    .append(request.getServerName())
                    .append(":")
                    .append(request.getServerPort())
                    .append(path);
        }

        @Override
        public String getServletPath() {
            return path;
        }
    }
}
