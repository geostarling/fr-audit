/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2016 ForgeRock AS.
 */
package org.forgerock.audit.handlers.elasticsearch;

import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.audit.AuditServiceBuilder.newAuditService;
import static org.forgerock.json.JsonValue.array;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.util.test.assertj.AssertJPromiseAssert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.InputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.forgerock.audit.AuditService;
import org.forgerock.audit.AuditServiceBuilder;
import org.forgerock.audit.DependencyProviderBase;
import org.forgerock.audit.events.EventTopicsMetaData;
import org.forgerock.audit.events.handlers.AuditEventHandler;
import org.forgerock.audit.json.AuditJsonConfig;
import org.forgerock.http.Client;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonPointer;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.CountPolicy;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.QueryResourceHandler;
import org.forgerock.json.resource.QueryResponse;
import org.forgerock.json.resource.Requests;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.query.QueryFilter;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

public class ElasticsearchAuditEventHandlerTest {

    private static final String RESOURCE_PATH = "/org/forgerock/audit/handlers/elasticsearch/";
    public static final int TOTAL_RESULTS = 1;
    public static final String ID = "id";

    private String authEventBeforeNormalization;

    @BeforeTest
    public void beforeTest() throws Exception {
        authEventBeforeNormalization = resourceAsJsonValue(
                RESOURCE_PATH + "authEventBeforeNormalization.json").toString();
    }

    @Test
    public void testSuccessfulQuery() throws Exception {

        // given
        final Promise<Response, NeverThrowsException> responsePromise = mock(Promise.class);
        final Client client = createClient(responsePromise);
        final AuditEventHandler handler = createElasticSearchAuditEventHandler(client);
        final QueryRequest queryRequest = Requests.newQueryRequest("access");
        final QueryResourceHandler queryResourceHandler = mock(QueryResourceHandler.class);
        final List<ResourceResponse> responses = new LinkedList<>();
        final JsonValue clientResponsePayload = json(object(
                field("hits", object(
                        field("total", TOTAL_RESULTS),
                        field("hits", array(object(
                                field("_index", "audit"),
                                field("_type", "access"),
                                field("_id", ID),
                                field("_source", object(
                                        field("transactionId", "transactionId"),
                                        field("timestamp", "timestamp")
                                ))
                        )))
                ))
        ));
        final Response clientResponse = createClientResponse(Status.OK, clientResponsePayload);

        queryRequest.setQueryFilter(QueryFilter.<JsonPointer>alwaysTrue());

        when(queryResourceHandler.handleResource(any(ResourceResponse.class))).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                if (invocation.getArguments()[0] instanceof ResourceResponse) {
                    responses.add((ResourceResponse) invocation.getArguments()[0]);
                    return true;
                } else {
                    return false;
                }
            }
        });
        when(responsePromise.get()).thenReturn(clientResponse);

        // when
        Promise<QueryResponse, ResourceException> result =
                handler.queryEvents(mock(Context.class), "access", queryRequest, queryResourceHandler);

        // then
        final QueryResponse queryResponse = result.get();
        assertThat(queryResponse.getPagedResultsCookie()).isEqualTo(null);
        assertThat(queryResponse.getTotalPagedResultsPolicy()).isEqualTo(CountPolicy.EXACT);
        assertThat(queryResponse.getTotalPagedResults()).isEqualTo(TOTAL_RESULTS);
        assertThat(responses.size()).isEqualTo(TOTAL_RESULTS);
        final ResourceResponse resourceResponse = responses.get(0);
        assertThat(resourceResponse.getId()).isEqualTo(ID);
        assertThat(resourceResponse.getContent().asMap()).isEqualTo(
                json(object(
                    field("transactionId", "transactionId"),
                    field("timestamp", "timestamp")
                )).asMap()
        );
    }

    @Test
    public void testFailedQuery() throws Exception {

        // given
        final Promise<Response, NeverThrowsException> responsePromise = mock(Promise.class);
        final Client client = createClient(responsePromise);
        final AuditEventHandler handler = createElasticSearchAuditEventHandler(client);
        final QueryRequest queryRequest = Requests.newQueryRequest("access");
        final QueryResourceHandler queryResourceHandler = mock(QueryResourceHandler.class);
        final Response clientResponse = createClientResponse(Status.INTERNAL_SERVER_ERROR, json(object()));

        queryRequest.setQueryFilter(QueryFilter.<JsonPointer>alwaysTrue());

        when(responsePromise.get()).thenReturn(clientResponse);

        // when
        Promise<QueryResponse, ResourceException> result =
                handler.queryEvents(mock(Context.class), "access", queryRequest, queryResourceHandler);

        // then
        assertThat(result).failedWithException().isInstanceOf(InternalServerErrorException.class);
    }

    @Test
    public void testRead() throws Exception {

        // given
        final JsonValue event = resourceAsJsonValue(RESOURCE_PATH + "authEventReadFromElasticsearch.json");
        final String resourceId = event.get(new JsonPointer("_id")).asString();
        final Response response = createClientResponse(Status.OK, event.toString());

        final Promise<Response, NeverThrowsException> promise = mock(Promise.class);
        when(promise.get()).thenReturn(response);

        final AuditEventHandler handler = createElasticSearchAuditEventHandler(createClient(promise));
        final Context context = mock(Context.class);

        // when
        final Promise<ResourceResponse, ResourceException> responsePromise =
                handler.readEvent(context, "authentication", resourceId);
        final ResourceResponse resourceResponse = responsePromise.get();

        // then
        assertThat(resourceResponse.getId()).isEqualTo(event.get("_id").asString());
        assertThat(resourceResponse.getContent().toString()).isEqualTo(authEventBeforeNormalization);
    }

    @Test
    public void testFailedRead() throws Exception {

        // given
        final Response response = createClientResponse(Status.NOT_FOUND, null);

        final Promise<Response, NeverThrowsException> promise = mock(Promise.class);
        when(promise.get()).thenReturn(response);

        final AuditEventHandler handler = createElasticSearchAuditEventHandler(createClient(promise));
        final Context context = mock(Context.class);

        // when
        final Promise<ResourceResponse, ResourceException> responsePromise =
                handler.readEvent(context, "authentication", "fake-id-that-does-not-exist");

        // then
        assertThat(responsePromise).failedWithException().isInstanceOf(NotFoundException.class);
    }

    @Test
    public void testSinglePublish() throws Exception {

        // given
        final Response response = new Response(Status.OK);

        final Promise<Response, NeverThrowsException> promise = mock(Promise.class);
        when(promise.get()).thenReturn(response);

        final AuditEventHandler handler = createElasticSearchAuditEventHandler(createClient(promise));
        final JsonValue event = resourceAsJsonValue(RESOURCE_PATH + "authEventBeforeNormalization.json");
        final String resourceId = event.get("_id").asString();
        final Context context = mock(Context.class);

        // when
        final Promise<ResourceResponse, ResourceException> responsePromise =
                handler.publishEvent(context, "authentication", event);
        final ResourceResponse resourceResponse = responsePromise.get();

        // then
        assertThat(resourceResponse.getId()).isEqualTo(resourceId);
        assertThat(resourceResponse.getContent().toString()).isEqualTo(authEventBeforeNormalization);
    }

    @Test
    public void testBatchPublish() throws Exception {

        // given
        final Response response = new Response(Status.OK);

        final Promise<Response, NeverThrowsException> promise = mock(Promise.class);
        when(promise.get()).thenReturn(response);

        final ElasticsearchAuditEventHandlerConfiguration config = new ElasticsearchAuditEventHandlerConfiguration();
        config.getBuffering().setEnabled(true);

        final AuditEventHandler handler = createElasticSearchAuditEventHandler(createClient(promise), config);
        final JsonValue event = resourceAsJsonValue(RESOURCE_PATH + "authEventBeforeNormalization.json");
        final String resourceId = event.get("_id").asString();
        final Context context = mock(Context.class);

        // when
        final Promise<ResourceResponse, ResourceException> responsePromise =
                handler.publishEvent(context, "authentication", event);
        final ResourceResponse resourceResponse = responsePromise.get();

        // then
        assertThat(resourceResponse.getId()).isEqualTo(resourceId);
        assertThat(resourceResponse.getContent().toString()).isEqualTo(authEventBeforeNormalization);
    }

    /**
     * Integration test.
     */
    @Test
    public void canConfigureCsvHandlerFromJsonAndRegisterWithAuditService() throws Exception {
        // given
        final AuditServiceBuilder auditServiceBuilder = newAuditService();

        final Client client = new Client(mock(Handler.class));
        DependencyProviderBase dependencyProvider = new DependencyProviderBase();
        dependencyProvider.register(Client.class, client);

        auditServiceBuilder.withDependencyProvider(dependencyProvider);
        final JsonValue config = AuditJsonConfig.getJson(
                getResource("/org/forgerock/audit/handlers/elasticsearch/event-handler-config.json"));

        // when
        AuditJsonConfig.registerHandlerToService(config, auditServiceBuilder);

        // then
        AuditService auditService = auditServiceBuilder.build();
        auditService.startup();
        try {
            AuditEventHandler registeredHandler = auditService.getRegisteredHandler("elasticsearch");
            assertThat(registeredHandler).isNotNull();
        } finally {
            auditService.shutdown();
        }
    }

    private AuditEventHandler createElasticSearchAuditEventHandler(final Client client) throws Exception {
        return createElasticSearchAuditEventHandler(client, new ElasticsearchAuditEventHandlerConfiguration());
    }

    private AuditEventHandler createElasticSearchAuditEventHandler(
            final Client client, final ElasticsearchAuditEventHandlerConfiguration configuration) throws Exception {
        configuration.setTopics(new HashSet<>(Arrays.asList("authentication", "access", "activity", "config")));
        return new ElasticsearchAuditEventHandler(configuration, getEventTopicsMetaData(), client);
    }

    private Client createClient(final Promise<Response, NeverThrowsException> promise) {
        final Handler handler = mock(Handler.class);
        final Client client = new Client(handler);
        when(handler.handle(any(Context.class), any(Request.class))).thenReturn(promise);
        return client;
    }

    private EventTopicsMetaData getEventTopicsMetaData() throws Exception {
        final JsonValue predefinedEventTypes = resourceAsJsonValue(RESOURCE_PATH + "events.json");
        final Map<String, JsonValue> events = new LinkedHashMap<>();
        for (final String eventTypeName : predefinedEventTypes.keys()) {
            events.put(eventTypeName, predefinedEventTypes.get(eventTypeName));
        }
        return new EventTopicsMetaData(events);
    }

    private Response createClientResponse(final Status status, final Object payload) {
        final Response response = new Response(status);
        if (payload != null) {
            response.setEntity(payload);
        }
        return response;
    }

    private JsonValue resourceAsJsonValue(final String resourcePath) throws Exception {
        try (final InputStream configStream = getClass().getResourceAsStream(resourcePath)) {
            return new JsonValue(new ObjectMapper().readValue(configStream, Map.class));
        }
    }

    private InputStream getResource(String resourceName) {
        return getClass().getResourceAsStream(resourceName);
    }
}
