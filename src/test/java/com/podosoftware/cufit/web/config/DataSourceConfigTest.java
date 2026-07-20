package com.podosoftware.cufit.web.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;

class DataSourceConfigTest {

    @Test
    void disablesLog4JdbcForLegacyPrefixedUrl() {
        DataSourceProperties properties = properties(
                "jdbc:log4jdbc:postgresql://localhost:5432/studio",
                DataSourceConfig.LOG4JDBC_DRIVER);

        DataSourceConfig.applyLoggingMode(properties, false);

        assertThat(properties.getUrl()).isEqualTo("jdbc:postgresql://localhost:5432/studio");
        assertThat(properties.getDriverClassName()).isNull();
    }

    @Test
    void enablesLog4JdbcForNativeUrl() {
        DataSourceProperties properties = properties("jdbc:postgresql://localhost:5432/studio", null);

        DataSourceConfig.applyLoggingMode(properties, true);

        assertThat(properties.getUrl()).isEqualTo("jdbc:log4jdbc:postgresql://localhost:5432/studio");
        assertThat(properties.getDriverClassName()).isEqualTo(DataSourceConfig.LOG4JDBC_DRIVER);
    }

    @Test
    void keepsAlreadyConfiguredLog4JdbcUrl() {
        DataSourceProperties properties = properties(
                "jdbc:log4jdbc:postgresql://localhost:5432/studio",
                DataSourceConfig.LOG4JDBC_DRIVER);

        DataSourceConfig.applyLoggingMode(properties, true);

        assertThat(properties.getUrl()).isEqualTo("jdbc:log4jdbc:postgresql://localhost:5432/studio");
        assertThat(properties.getDriverClassName()).isEqualTo(DataSourceConfig.LOG4JDBC_DRIVER);
    }

    @Test
    void rejectsNonJdbcUrlWhenLoggingIsEnabled() {
        DataSourceProperties properties = properties("postgresql://localhost:5432/studio", null);

        assertThatThrownBy(() -> DataSourceConfig.applyLoggingMode(properties, true))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("jdbc: prefix");
    }

    private DataSourceProperties properties(String url, String driverClassName) {
        DataSourceProperties properties = new DataSourceProperties();
        properties.setUrl(url);
        properties.setDriverClassName(driverClassName);
        return properties;
    }
}
