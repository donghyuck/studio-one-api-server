package com.podosoftware.cufit.web.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.bind.PropertySourcesPlaceholdersResolver;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;

import studio.one.platform.ai.autoconfigure.config.AiAdapterProperties;
import studio.one.platform.ai.autoconfigure.config.ModelDeploymentProperties;
import studio.one.platform.ai.autoconfigure.config.RagEmbeddingProperties;
import studio.one.platform.ai.model.ModelDefinition;
import studio.one.platform.ai.model.ModelWorkload;
import studio.one.platform.ai.model.catalog.BuiltInModelCatalog;
import studio.one.platform.ai.model.embedding.EmbeddingSpaceContract;
import studio.one.platform.ai.model.embedding.EmbeddingSpaceId;

class AiModelDeploymentConfigurationSnapshotTest {

    private static final Map<String, DeploymentSnapshot> EXPECTED = Map.of(
            "chat-default", new DeploymentSnapshot("google-ai", "gemini-2.5-flash", null, null),
            "chat-pro", new DeploymentSnapshot("google-ai", "gemini-2.5-pro", null, null),
            "local-gemma-v1", new DeploymentSnapshot("local-gemma", "gemma-3-4b", null, null),
            "humanities-text-v1", new DeploymentSnapshot(
                    "google-ai", "gemini-embedding-001", 768,
                    "es:v1:af68e66cba4cd2f685a1a2c5d3f9f43e1859c70926ac26f62449274626a7b068"),
            "document-multimodal-v1", new DeploymentSnapshot(
                    "google-ai", "gemini-embedding-2", 768,
                    "es:v1:1649bfdabe493e3a20e5078719dbe0577fbcca494cef88fd4acab1ab77374afa"),
            "retrieval-ko-kure-v1", new DeploymentSnapshot(
                    "kure", "nlpai-lab/KURE-v1", 1024,
                    "es:v1:eb99a8ed70abc5da4e432ea48281ce949c04602df3c38f70c58eb651d7d6a08a"));

    @Test
    void devDeploymentIdsResolveToReviewedModelsAndEmbeddingSpaces() throws IOException {
        Binder binder = binder("config/application-dev.yml");
        assertThat(binder.bind("spring.cache.type", Bindable.of(String.class))
                .orElseThrow(() -> new IllegalStateException("spring.cache.type is missing")))
                .isEqualTo("caffeine");
        ModelDeploymentProperties properties = binder.bind(
                "studio.ai", Bindable.of(ModelDeploymentProperties.class))
                .orElseThrow(() -> new IllegalStateException("studio.ai deployment configuration is missing"));
        AiAdapterProperties adapters = binder.bind(
                "studio.ai", Bindable.of(AiAdapterProperties.class))
                .orElseThrow(() -> new IllegalStateException("studio.ai provider configuration is missing"));
        RagEmbeddingProperties ragEmbedding = binder.bind(
                "studio.ai.rag", Bindable.of(RagEmbeddingProperties.class))
                .orElseThrow(() -> new IllegalStateException("studio.ai.rag embedding configuration is missing"));

        assertThat(properties.getRouting().getDefaultChatDeployment()).isEqualTo("chat-default");
        assertThat(properties.getRouting().getDefaultEmbeddingDeployment()).isEqualTo("humanities-text-v1");
        assertThat(ragEmbedding.getDefaultEmbeddingProfile())
                .isEqualTo("google-ai/gemini-embedding-001@768");
        assertThat(ragEmbedding.getEmbeddingProfiles()).containsKeys(
                "google-ai/gemini-embedding-001@768",
                "google-ai/gemini-embedding-2@768");
        assertThat(adapters.getProviders()).containsOnlyKeys("google-ai", "local-gemma", "kure");
        adapters.getProviders().values().forEach(provider -> {
            assertThat(provider.getChat().getModel()).isNull();
            assertThat(provider.getEmbedding().getModel()).isNull();
            assertThat(provider.getEmbedding().getDimension()).isNull();
        });

        assertThat(snapshot(properties)).containsExactlyInAnyOrderEntriesOf(EXPECTED);
    }

    @Test
    void rollbackFixturePreservesPreviousDefaultRoutingMeaning() throws IOException {
        Binder binder = binder("config/application-ai-legacy-rollback.yml");
        AiAdapterProperties legacy = binder.bind(
                "studio.ai", Bindable.of(AiAdapterProperties.class))
                .orElseThrow(() -> new IllegalStateException("legacy studio.ai configuration is missing"));

        AiAdapterProperties.Provider legacyChat = legacy.getProviders().get(
                legacy.getRouting().getDefaultChatProvider());
        AiAdapterProperties.Provider legacyEmbedding = legacy.getProviders().get(
                legacy.getRouting().getDefaultEmbeddingProvider());

        assertThat(legacyChat.getChat().getModel()).isEqualTo(EXPECTED.get("chat-default").apiModel());
        assertThat(legacyEmbedding.getEmbedding().getModel())
                .isEqualTo(EXPECTED.get("humanities-text-v1").apiModel());
        assertThat(legacyEmbedding.getEmbedding().getDimension())
                .isEqualTo(EXPECTED.get("humanities-text-v1").dimension());
    }

    private Map<String, DeploymentSnapshot> snapshot(ModelDeploymentProperties properties) {
        var catalog = BuiltInModelCatalog.load();
        Map<String, DeploymentSnapshot> result = new LinkedHashMap<>();
        properties.getModelDeployments().forEach((deploymentId, deployment) -> {
            ModelDefinition definition = catalog.find(deployment.getModelRef()).orElseThrow();
            Integer dimension = deployment.getDimension() == null
                    ? definition.dimensionPolicy().defaultDimension() : deployment.getDimension();
            String spaceId = deployment.getWorkload() == ModelWorkload.EMBEDDING
                    ? EmbeddingSpaceId.from(new EmbeddingSpaceContract(
                            "v1", definition.providerFamily(), definition.apiModel(), dimension,
                            deployment.getNormalizationPolicy(), deployment.getIndexTaskType(),
                            deployment.getQueryTaskType(), deployment.getInputTransformId(),
                            deployment.getInputTransformVersion(), deployment.getSemanticOptions()))
                    : null;
            result.put(deploymentId, new DeploymentSnapshot(
                    deployment.getProviderRef(), definition.apiModel(), dimension, spaceId));
        });
        return result;
    }

    private Binder binder(String resource) throws IOException {
        List<PropertySource<?>> loaded = new YamlPropertySourceLoader().load(
                resource, new ClassPathResource(resource));
        MutablePropertySources sources = new MutablePropertySources();
        loaded.forEach(sources::addLast);
        return new Binder(
                ConfigurationPropertySources.from(sources),
                new PropertySourcesPlaceholdersResolver(sources));
    }

    private record DeploymentSnapshot(
            String providerRef, String apiModel, Integer dimension, String embeddingSpaceId) {
    }
}
