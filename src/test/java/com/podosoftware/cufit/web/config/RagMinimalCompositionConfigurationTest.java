package com.podosoftware.cufit.web.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.io.ClassPathResource;

class RagMinimalCompositionConfigurationTest {
    @Test
    void minimalOverlayDisablesExtensionsAndKeepsRequiredSchemaLocations() throws Exception {
        var loader = new YamlPropertySourceLoader();
        var sources = new MutablePropertySources();
        loader.load("minimal", new ClassPathResource("config/application-rag-minimal.yml"))
                .forEach(sources::addLast);
        loader.load("dev", new ClassPathResource("config/application-dev.yml"))
                .forEach(sources::addLast);
        var binder = new Binder(ConfigurationPropertySources.from(sources));
        for (String feature : List.of("mail", "template", "wiki", "avatar-image", "skillgraph")) {
            assertThat(binder.bind("studio.features." + feature + ".enabled", Boolean.class).get()).isFalse();
        }
        assertThat(binder.bind("studio.ai.vector.projection.enabled", Boolean.class).get()).isFalse();
        assertThat(binder.bind("studio.features.team.enabled", Boolean.class).get()).isTrue();
        assertThat(binder.bind("studio.features.workspace.enabled", Boolean.class).get()).isTrue();
        var locations = binder.bind("spring.flyway.locations", Bindable.listOf(String.class)).get();
        assertThat(locations).contains("classpath:/schema/team/postgres", "classpath:/schema/ai/postgres",
                "classpath:/schema/attachment/postgres", "classpath:/schema/web-knowledge/postgres");
        assertThat(locations).noneMatch(location -> location.matches(".*(skillgraph|avatar|template|mail|wiki)/postgres"));
        assertThat(binder.bind("spring.flyway.validate-on-migrate", Boolean.class).get()).isTrue();
    }
}
