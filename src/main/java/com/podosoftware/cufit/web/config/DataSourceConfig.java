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
 *      @file DataSourceConfig.java
 *      @date 2025
 *
 */
package com.podosoftware.cufit.web.config;
 
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.jdbc.autoconfigure.DataSourceProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;

@Configuration
@ConditionalOnClass(name = "javax.sql.DataSource")
@EnableConfigurationProperties(DataSourceLoggingProperties.class)
public class DataSourceConfig {

    static final String LOG4JDBC_PREFIX = "jdbc:log4jdbc:";
    static final String JDBC_PREFIX = "jdbc:";
    static final String LOG4JDBC_DRIVER = "net.sf.log4jdbc.sql.jdbcapi.DriverSpy";

    @Bean(name = "primaryDataSourceProperties")
    @ConfigurationProperties("spring.datasource.primary")
    public DataSourceProperties primaryDataSourceProperties() {
        return new DataSourceProperties();
    }

    @Primary
    @Bean(name = "primaryDataSource")
    public javax.sql.DataSource dataSource(
            @Qualifier("primaryDataSourceProperties") DataSourceProperties properties,
            DataSourceLoggingProperties loggingProperties) {
        applyLoggingMode(properties, loggingProperties.isEnabled());
        return properties
                .initializeDataSourceBuilder()
                .build();
    }

    static void applyLoggingMode(DataSourceProperties properties, boolean enabled) {
        String url = properties.getUrl();
        if (url == null || url.isBlank()) {
            return;
        }
        if (enabled) {
            properties.setUrl(toLog4JdbcUrl(url));
            properties.setDriverClassName(LOG4JDBC_DRIVER);
            return;
        }
        properties.setUrl(toNativeJdbcUrl(url));
        if (LOG4JDBC_DRIVER.equals(properties.getDriverClassName())) {
            properties.setDriverClassName(null);
        }
    }

    private static String toLog4JdbcUrl(String url) {
        if (url.startsWith(LOG4JDBC_PREFIX)) {
            return url;
        }
        if (url.startsWith(JDBC_PREFIX)) {
            return LOG4JDBC_PREFIX + url.substring(JDBC_PREFIX.length());
        }
        throw new IllegalArgumentException("Unsupported JDBC URL: expected a jdbc: prefix");
    }

    private static String toNativeJdbcUrl(String url) {
        if (url.startsWith(LOG4JDBC_PREFIX)) {
            return JDBC_PREFIX + url.substring(LOG4JDBC_PREFIX.length());
        }
        return url;
    }

    @Bean(name = "transactionManager")
    @Primary
    public PlatformTransactionManager transactionManager(@Qualifier("primaryDataSource") DataSource dataSource) {
        return new DataSourceTransactionManager(dataSource);
    }
}
