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

import static org.forgerock.json.resource.Responses.newQueryResponse;
import static org.forgerock.json.resource.Responses.newResourceResponse;

import org.forgerock.audit.Audit;
import org.forgerock.audit.events.EventTopicsMetaData;
import org.forgerock.audit.events.handlers.AuditEventHandlerBase;
import org.forgerock.http.Client;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.QueryResourceHandler;
import org.forgerock.json.resource.QueryResponse;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.Promise;

public class ElasticsearchAuditEventHandler extends AuditEventHandlerBase {

    public ElasticsearchAuditEventHandler(
            final ElasticsearchAuditEventHandlerConfiguration configuration,
            final EventTopicsMetaData eventTopicsMetaData,
            @Audit final Client client
    ) {
        super(configuration.getName(), eventTopicsMetaData, configuration.getTopics(), configuration.isEnabled());

    }

    @Override
    public void startup() throws ResourceException {
        // do nothing
    }

    @Override
    public void shutdown() throws ResourceException {
        // do nothing
    }

    @Override
    public Promise<QueryResponse, ResourceException> queryEvents(Context context, String topic, QueryRequest query,
            QueryResourceHandler handler) {
        return newQueryResponse().asPromise();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> readEvent(Context context, String topic, String resourceId) {
        return newResourceResponse(resourceId, null, null).asPromise();
    }

    @Override
    public Promise<ResourceResponse, ResourceException> publishEvent(Context context, String topic, JsonValue event) {
        return newResourceResponse(event.get(ResourceResponse.FIELD_CONTENT_ID).asString(), null, event).asPromise();
    }
}
