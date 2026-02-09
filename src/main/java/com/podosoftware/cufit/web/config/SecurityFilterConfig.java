/**
 *
 *      Copyright 2025
 *
 *      Licensed under the Apache License, Version 2.0 (the 'License');
 *      you may not use this file except in compliance with the License.
 *      You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing, software
 *      distributed under the License is distributed on an 'AS IS' BASIS,
 *      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *      See the License for the specific language governing permissions and
 *      limitations under the License.
 *
 *      @file SecurityFilterConfig.java
 *      @date 2025
 *
 */

package com.podosoftware.cufit.web.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import studio.one.base.security.handler.ApplicationAccessDeniedHandler;
import studio.one.base.security.handler.ApplicationAuthenticationEntryPoint;
import studio.one.base.security.handler.AuthenticationErrorHandler;
import studio.one.base.security.jwt.JwtAuthenticationFilter;
import studio.one.base.security.jwt.JwtTokenProvider;
import studio.one.platform.constant.PropertyKeys;
import studio.one.platform.constant.ServiceNames;
import studio.one.platform.security.autoconfigure.FormLoginProperties;
import studio.one.platform.security.autoconfigure.JwtProperties;
import studio.one.platform.security.autoconfigure.LogoutProperties;
import studio.one.platform.security.autoconfigure.SecurityProperties;
import studio.one.platform.util.LogUtils;

/**
 *
 * @author  donghyuck, son
 * @since 2025-12-30
 * @version 1.0
 *
 * <pre> 
 * {@literal << 개정이력(Modification Information) >>}
 *   수정일        수정자           수정내용
 *  ---------    --------    ---------------------------
 * 2025-12-30  donghyuck, son: 최초 생성.
 * </pre>
 */

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableConfigurationProperties(SecurityProperties.class)
@RequiredArgsConstructor
@Slf4j
public class SecurityFilterConfig {

    private final CorsConfigurationSource corsConfigurationSource;
    private final SecurityProperties securityProperties;
    private final AuthenticationErrorHandler authenticationErrorHandler;

    /**
     * Spring Security의 필터 체인을 정의합니다.
     *
     * <ul>
     * <li>CSRF 보호 비활성화 (JWT 기반 stateless 서버)</li>
     * <li>CORS 정책 적용</li>
     * <li>세션 관리 정책: STATELESS</li>
     * <li>permitAll, 역할별 경로, 그 외 인증 필요 경로 설정</li>
     * <li>JWT 인증 필터 적용</li>
     * <li>예외 처리 핸들러 적용</li>
     * </ul>
     *
     * @param http                       HttpSecurity 객체
     * @param authenticationManager      인증 매니저
     * @param jwtTokenProvider           JWT 토큰 프로바이더
     * @param userDetailsService         사용자 정보 서비스
     * @param authenticationErrorHandler 인증 에러 핸들러
     * @return SecurityFilterChain
     * @throws Exception 설정 중 오류 발생 시
     */
    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurityFilterChain(
            HttpSecurity http,
            AuthenticationManager authenticationManager,
            ObjectProvider<JwtTokenProvider> jwtTokenProvider,
            @Qualifier(ServiceNames.USER_DETAILS_SERVICE) UserDetailsService userDetailsService,
            AuthenticationErrorHandler authenticationErrorHandler)
            throws Exception {
        log.info(LogUtils.blue("Configuring API SecurityFilterChain with ..."));
        if (jwtTokenProvider.getIfAvailable() == null) {
            log.warn(LogUtils.red("JwtTokenProvider is not available. JWT Authentication will be disabled."));
        }
        FormLoginProperties formLogin = securityProperties.getFormLogin();
        LogoutProperties logout = securityProperties.getLogout();
        JwtTokenProvider provider = jwtTokenProvider.getIfAvailable();
        JwtProperties jwtProps = securityProperties.getJwt();

        HttpSecurity configured = http
                .antMatcher("/api/**")
                // .csrf(csrf -> csrf.ignoringAntMatchers(
                //         buildCsrfIgnored(formLogin, logout, jwtProps).toArray(new String[0])))
                .csrf(xcsrf-> xcsrf.disable()   )
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authz -> {
                    for (String pattern : jwtOpenPatterns(securityProperties)) {
                        authz.antMatchers(pattern).permitAll();
                    }
                    securityProperties.getPermit().getPermitAll().forEach(path -> {
                        authz.antMatchers(path).permitAll();
                    });
                    securityProperties.getPermit().getRole().forEach((role, paths) -> paths.forEach(path -> {
                        authz.antMatchers(path).hasRole(role);
                    }));
                    authz.anyRequest().authenticated();
                })
                .exceptionHandling(this::configureExceptionHandling)
                .authenticationManager(authenticationManager);

        configured.formLogin(AbstractHttpConfigurer::disable);
        configured.logout(AbstractHttpConfigurer::disable);
        if (provider != null) {
            log.debug("JwtAuthenticationFilter is being added to the filter chain.");
            JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(
                    securityProperties.getJwt().getEndpoints().getBasePath(), provider, userDetailsService,
                    authenticationErrorHandler);
            configured.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        } else {
            log.debug("JwtAuthenticationFilter is NOT added to the filter chain.");
        }
        logPermitSummary("apiSecurityFilterChain");
        return configured.build();
    }

    @Bean
    @Order(2)
    @ConditionalOnProperty(prefix = PropertyKeys.Security.PREFIX
            + ".form-login", name = "enabled", havingValue = "true")
    public SecurityFilterChain webSecurityFilterChain(
            HttpSecurity http,
            AuthenticationManager authenticationManager)
            throws Exception {
        log.info(LogUtils.blue("Configuring Web SecurityFilterChain..."));
        FormLoginProperties formLogin = securityProperties.getFormLogin();
        LogoutProperties logout = securityProperties.getLogout();
        JwtProperties jwtProps = securityProperties.getJwt();
        HttpSecurity configured = http
                .antMatcher("/**")
                .csrf(csrf -> csrf.ignoringAntMatchers(
                        buildCsrfIgnored(formLogin, logout, jwtProps).toArray(new String[0])))
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(authz -> {
                    if (formLogin.isEnabled()) {
                        authz.antMatchers(formLogin.getLoginPage()).permitAll();
                        authz.antMatchers(formLogin.getLoginProcessingUrl()).permitAll();
                    }
                    if (logout.isEnabled()) {
                        authz.antMatchers(logout.getLogoutUrl()).permitAll();
                    }
                    securityProperties.getPermit().getPermitAll().forEach(path -> {
                        authz.antMatchers(path).permitAll();
                    });
                    securityProperties.getPermit().getRole().forEach((role, paths) -> paths.forEach(path -> {
                        authz.antMatchers(path).hasRole(role);
                    }));
                    authz.anyRequest().authenticated();
                })
                .exceptionHandling(this::configureExceptionHandling)
                .authenticationManager(authenticationManager);

        if (formLogin.isEnabled()) {
            configured.formLogin(form -> form
                    .loginPage(formLogin.getLoginPage())
                    .loginProcessingUrl(formLogin.getLoginProcessingUrl())
                    .usernameParameter(formLogin.getUsernameParameter())
                    .passwordParameter(formLogin.getPasswordParameter())
                    .defaultSuccessUrl(formLogin.getDefaultSuccessUrl(), true)
                    .permitAll());
        }
        if (logout.isEnabled()) {
            configured.logout(config -> {
                config.logoutUrl(logout.getLogoutUrl())
                        .logoutSuccessUrl(logout.getLogoutSuccessUrl())
                        .invalidateHttpSession(logout.isInvalidateSession())
                        .permitAll();
                if (!logout.getDeleteCookies().isEmpty()) {
                    config.deleteCookies(logout.getDeleteCookies().toArray(new String[0]));
                }
            });
        } 
        logPermitSummary("webSecurityFilterChain");
        return configured.build();
    }

    private static List<String> buildCsrfIgnored(
            FormLoginProperties formLogin,
            LogoutProperties logout,
            JwtProperties jwtProps) {
        List<String> csrfIgnored = new ArrayList<>();
        csrfIgnored.add(formLogin.getLoginProcessingUrl());
        csrfIgnored.add(logout.getLogoutUrl());
        if (jwtProps != null && jwtProps.isEnabled() && jwtProps.getPermit() != null) {
            jwtProps.getPermit().forEach(path -> csrfIgnored.add(normalize(path)));
        }
        return csrfIgnored;
    }

    private void logPermitSummary(String chainName) {
        List<String> permitAll = securityProperties.getPermit().getPermitAll();
        var rolePermits = securityProperties.getPermit().getRole();
        List<String> jwtOpen = jwtOpenPatterns(securityProperties);
        JwtProperties jwtProps = securityProperties.getJwt();
        List<String> jwtPermit = new ArrayList<>();
        if (jwtProps != null && jwtProps.getPermit() != null) {
            jwtProps.getPermit().forEach(path -> jwtPermit.add(normalize(path)));
        }
        log.info(
                "Security permit summary for {}\n  permitAll={}\n  rolePermits={}\n  jwtOpen={}\n  jwtPermit={}",
                chainName, permitAll, rolePermits, jwtOpen, jwtPermit);
    }

    private static List<String> jwtOpenPatterns(SecurityProperties securityProperties) {
        JwtProperties p = securityProperties.getJwt();
        String base = normalize(p.getEndpoints().getBasePath()); // 예: "/auth"
        List<String> out = new ArrayList<>();
        if (p.isEnabled()) {
            if (p.getEndpoints().isLoginEnabled())
                out.add(base + "/login");
            if (p.getEndpoints().isRefreshEnabled())
                out.add(base + "/refresh");
            if (p.getPermit() != null) {
                p.getPermit().forEach(path -> out.add(normalize(path)));
            }
        }
        return out;
    }

    private static String normalize(String s) {
        if (s == null || s.isEmpty())
            return "/auth";
        return s.startsWith("/") ? s : "/" + s;
    }

    /**
     * 인증/인가 예외 처리 핸들러를 설정합니다.
     *
     * @param exceptions ExceptionHandlingConfigurer
     */
    private void configureExceptionHandling(ExceptionHandlingConfigurer<HttpSecurity> exceptions) {
        exceptions
                .accessDeniedHandler(new ApplicationAccessDeniedHandler(authenticationErrorHandler))
                .authenticationEntryPoint(
                        new ApplicationAuthenticationEntryPoint(authenticationErrorHandler));
    }

}
