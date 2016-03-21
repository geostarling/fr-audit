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

package org.forgerock.audit.handlers.jms;

import static org.forgerock.audit.util.ResourceExceptionsUtil.*;
import static org.forgerock.json.JsonValue.*;
import static org.forgerock.json.resource.Responses.newResourceResponse;

import javax.inject.Inject;
import javax.jms.ConnectionFactory;
import javax.jms.JMSException;
import javax.jms.MessageProducer;
import javax.jms.Session;
import javax.jms.Topic;
import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.forgerock.audit.Audit;
import org.forgerock.audit.events.EventTopicsMetaData;
import org.forgerock.audit.events.handlers.AuditEventHandlerBase;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.NotSupportedException;
import org.forgerock.json.resource.QueryRequest;
import org.forgerock.json.resource.QueryResourceHandler;
import org.forgerock.json.resource.QueryResponse;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.json.resource.ResourceResponse;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Publishes Audit events on a JMS Topic.
 */
public class JmsAuditEventHandler extends AuditEventHandlerBase {
    private static final Logger logger = LoggerFactory.getLogger(JmsAuditEventHandler.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    private final JmsContextManager jmsContextManager;
    private final Publisher<JsonValue> publisher;

    /**
     * Creates a new AuditEventHandler instance that publishes JMS messages on a JMS Topic for each Audit event.
     *
     * @param connectionFactory optional injected connection factory.
     * @param topic optional injected jms topic.
     * @param configuration Configuration parameters that can be adjusted by system administrators.
     * @param eventTopicsMetaData Meta-data for all audit event topics.
     */
    @Inject
    public JmsAuditEventHandler(
            @Audit final ConnectionFactory connectionFactory,
            @Audit final Topic topic,
            final JmsAuditEventHandlerConfiguration configuration,
            final EventTopicsMetaData eventTopicsMetaData) throws ResourceException {

        super(configuration.getName(), eventTopicsMetaData, configuration.getTopics(), configuration.isEnabled());
        Reject.ifNull(configuration.getProviderUrl(), "JMS providerUrl is required");
        Reject.ifNull(configuration.getJmsTopic(), "JMS publish topic is required");
        Reject.ifNull(configuration.getInitialContextFactory(), "JMS provider connection context factory is required.");

        publisher = buildPublisher(configuration);
        jmsContextManager = buildContextManager(configuration, connectionFactory, topic);

        logger.debug("Successfully configured JMS audit event handler.");
    }

    /**
     * Factory method for the JMS Context Manager.
     *
     * @param configuration the configuration of the handler.
     * @param connectionFactory connection factory for the context manager to manage, if not null.
     * @param topic the jms topic for the context manager to manage, if not null.
     * @return the constructed JmsContextManager.
     * @throws ResourceException if there is trouble constructing the JMS ContextManager.
     */
    JmsContextManager buildContextManager(JmsAuditEventHandlerConfiguration configuration,
            ConnectionFactory connectionFactory, Topic topic) throws ResourceException {
        return new JmsContextManager(configuration, connectionFactory, topic);
    }

    /**
     * Factory method for publisher.
     *
     * @param configuration used to determine if a batched publisher is needed or not.
     * @return the constructed publisher.
     */
    Publisher<JsonValue> buildPublisher(JmsAuditEventHandlerConfiguration configuration) {
        return configuration.isBatchEnabled()
                ? new JmsBatchPublisher(configuration.getBatchConfiguration())
                : new JmsPublisher();
    }

    /**
     * Creates the JMS Topic and ConnectionFactory from the context configuration settings and opens the JMS connection.
     */
    @Override
    public void startup() throws ResourceException {
        publisher.startup();
        logger.debug("JMS audit event handler is started.");
    }

    /**
     * Closes the JMS connection.
     */
    @Override
    public void shutdown() throws ResourceException {
        publisher.shutdown();
        logger.debug("JMS audit event handler is shutdown.");
    }

    @Override
    public boolean canBeUsedForQueries() {
        // JMS does not support Query or Read.
        return false;
    }

    /**
     * Converts the audit event into a JMS TextMessage and then publishes the message on the configured jmsTopic.
     *
     * @param context The context chain that initiated the event.
     * @param auditTopic The Audit Topic for which the auditEvent was created for. (Not to be confused with a JMS Topic)
     * @param auditEvent The event to convert to a JMS TextMessage and publish on the JMS Topic.
     * @return a promise with either a response or an exception
     */
    public Promise<ResourceResponse, ResourceException> publishEvent(Context context, String auditTopic,
            JsonValue auditEvent) {
        try {
            publisher.publish(json(object(
                    field("auditTopic", auditTopic),
                    field("event", auditEvent.getObject())
            )));

            // Return the auditEvent as the response.
            return newResourceResponse(
                    auditEvent.get(ResourceResponse.FIELD_CONTENT_ID).asString(),
                    null,
                    auditEvent).asPromise();

        } catch (Exception ex) {
            return adapt(ex).asPromise();
        }
    }

    /**
     * Publishes the list of messages using a single producer.
     *
     * @param messages the messages to send.
     */
    private void publishJmsMessages(List<JsonValue> messages) {
        try (Session session = jmsContextManager.createSession()) {
            try (MessageProducer producer = jmsContextManager.createProducer(session)) {
                for (JsonValue message : messages) {
                    String text = mapper.writeValueAsString(message.getObject());
                    try {
                        producer.send(session.createTextMessage(text));
                    } catch (JMSException e) {
                        logger.error("unable to publish message " + text, e);
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Unable to publish JMS messages, messages are likely lost: " + messages, e);
        }
    }

    /**
     * Returns NotSupportedException as query is not implemented for JMS.
     * <br/>
     * {@inheritDoc}
     * @return NotSupportedException as query is not implemented for JMS.
     */
    @Override
    public Promise<QueryResponse, ResourceException> queryEvents(
            Context context,
            String topic,
            QueryRequest queryRequest,
            QueryResourceHandler queryResourceHandler) {
        return notSupported(queryRequest).asPromise();
    }

    /**
     * Returns NotSupportedException as read is not implemented for JMS.
     * <br/>
     * {@inheritDoc}
     * @return NotSupportedException as read is not implemented for JMS.
     */
    @Override
    public Promise<ResourceResponse, ResourceException> readEvent(Context context, String topic, String resourceId) {
        return new NotSupportedException("read operations are not supported").asPromise();
    }

    /**
     * Implementation of the BatchPublisher to handle publishing groups of audit event data to JMS.
     */
    private class JmsBatchPublisher extends BatchPublisher<JsonValue> {

        /**
         * Constructor that passes the configuration to {@link BatchPublisher}
         *
         * @param configuration config of the publisher.
         */
        public JmsBatchPublisher(BatchPublisherConfiguration configuration) {
            super("JmsBatchPublisher", configuration);
        }

        @Override
        public void startupPublisher() throws ResourceException {
            openJmsConnection();
        }

        @Override
        public void shutdownPublisher() throws ResourceException {
            closeJmsConnection();
        }

        @Override
        protected void publishMessages(List<JsonValue> messages) {
            publishJmsMessages(messages);
        }
    }

    /**
     * Implementation of the Publisher to handle publishing singleton audit event data to JMS.
     */
    private class JmsPublisher implements Publisher<JsonValue> {

        @Override
        public void startup() throws ResourceException {
            openJmsConnection();
        }

        @Override
        public void shutdown() throws ResourceException {
            closeJmsConnection();
        }

        @Override
        public void publish(JsonValue message) throws ResourceException {
            publishJmsMessages(Collections.singletonList(message));
        }
    }

    private void openJmsConnection() throws InternalServerErrorException {
        try {
            jmsContextManager.openConnection();
        } catch (JMSException e) {
            throw new InternalServerErrorException("trouble opening connection", e);
        }
    }

    private void closeJmsConnection() throws InternalServerErrorException {
        try {
            jmsContextManager.closeConnection();
        } catch (JMSException e) {
            throw new InternalServerErrorException("trouble closing connection", e);
        }
    }
}
