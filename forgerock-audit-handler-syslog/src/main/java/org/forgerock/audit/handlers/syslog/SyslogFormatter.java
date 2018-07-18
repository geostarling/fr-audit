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
 * Copyright 2013 Cybernetica AS
 * Portions copyright 2014-2015 ForgeRock AS.
 */
package org.forgerock.audit.handlers.syslog;

import static org.forgerock.audit.events.AuditEventBuilder.*;
import static org.forgerock.audit.events.AuditEventHelper.getAuditEventSchema;
import static org.forgerock.audit.util.JsonSchemaUtils.generateJsonPointers;

import org.forgerock.audit.events.EventTopicsMetaData;
import org.forgerock.audit.handlers.syslog.formatters.StructuredDataFormatter;
import org.forgerock.audit.providers.LocalHostNameProvider;
import org.forgerock.audit.providers.ProductInfoProvider;
import org.forgerock.audit.events.AuditEvent;
import org.forgerock.audit.handlers.syslog.SyslogAuditEventHandlerConfiguration.SeverityFieldMapping;
import org.forgerock.json.JsonPointer;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.util.Reject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Responsible for formatting an {@link AuditEvent}'s JSON representation as an RFC-5424 compliant Syslog message.
 *
 * Objects are immutable and can therefore be freely shared across threads without synchronization.
 *
 * @see <a href="https://tools.ietf.org/html/rfc5424">RFC-5424</a>
 */
class SyslogFormatter {

    private static final Logger logger = LoggerFactory.getLogger(SyslogFormatter.class);

    private static final String SYSLOG_SPEC_VERSION = "1";
    private static final String NIL_VALUE = "-";

    private final Map<String, StructuredDataFormatter> structuredDataFormatters;
    private final Map<String, SeverityFieldMapping> severityFieldMappings;
    private final String hostname;
    private final String appName;
    private final String procId;
    private final Facility facility;

    /**
     * Construct a new SyslogFormatter.
     *
     * @param eventTopicsMetaData Schemas and additional meta-data for known audit event topics.
     * @param config Configuration options.
     * @param localHostNameProvider Strategy for obtaining hostname of current server.
     * @param productInfoProvider Strategy for obtaining name of the hosting application.
     */
    public SyslogFormatter(EventTopicsMetaData eventTopicsMetaData, SyslogAuditEventHandlerConfiguration config,
            LocalHostNameProvider localHostNameProvider, ProductInfoProvider productInfoProvider) {

        Reject.ifNull(localHostNameProvider, "LocalHostNameProvider must not be null");

        this.hostname = getLocalHostName(localHostNameProvider);
        this.procId = String.valueOf(SyslogFormatter.class.hashCode());
        this.appName = getProductName(productInfoProvider);
        this.facility = config.getFacility();
        this.severityFieldMappings =
                createSeverityFieldMappings(config.getSeverityFieldMappings(), eventTopicsMetaData);
        this.structuredDataFormatters = Collections.unmodifiableMap(
                createStructuredDataFormatters(appName, eventTopicsMetaData, config.getStructuredDataFormatterClass()));
    }

    /**
     * Translate the provided <code>auditEvent</code> to an RFC-5424 compliant Syslog message.
     *
     * @param topic The topic of the provided <code>auditEvent</code>.
     * @param auditEvent The audit event to be formatted.
     *
     * @return an RFC-5424 compliant Syslog message.
     *
     * @throws IllegalArgumentException If this formatter has no meta-data for the specified <code>topic</code>.
     */
    public String format(String topic, JsonValue auditEvent) {

        Reject.ifFalse(canFormat(topic), "Unknown event topic");

        final Severity severity = getSeverityLevel(topic, auditEvent);
        final String priority = String.valueOf(calculatePriorityValue(facility, severity));
        final String timestamp = auditEvent.get(TIMESTAMP).asString();
        final String msgId = auditEvent.get(EVENT_NAME).asString();
        final String structuredData = structuredDataFormatters.get(topic).format(auditEvent);
        final String msg = "";

        return "<" + priority + ">"         // https://tools.ietf.org/html/rfc5424#section-6.2.1    PRI
                + SYSLOG_SPEC_VERSION + " " // https://tools.ietf.org/html/rfc5424#section-6.2.2    VERSION
                + timestamp + " "           // https://tools.ietf.org/html/rfc5424#section-6.2.3    TIMESTAMP
                + hostname + " "            // https://tools.ietf.org/html/rfc5424#section-6.2.4    HOSTNAME
                + appName + " "             // https://tools.ietf.org/html/rfc5424#section-6.2.5    APP-NAME
                + procId + " "              // https://tools.ietf.org/html/rfc5424#section-6.2.6    PROCID
                + msgId + " "               // https://tools.ietf.org/html/rfc5424#section-6.2.7    MSGID
                + structuredData + " "      // https://tools.ietf.org/html/rfc5424#section-6.3      STRUCTURED-DATA
                + msg;                      // https://tools.ietf.org/html/rfc5424#section-6.4      MSG
    }

    /**
     * Returns <code>true</code> if this formatter has been configured to handle events of the specified topic.
     *
     * @param topic The topic of the <code>auditEvent</code> to be formatted.
     *
     * @return <code>true</code> if this formatter has been configured to handle events of the specified topic;
     *         <code>false</code> otherwise.
     */
    public boolean canFormat(String topic) {
        return structuredDataFormatters.containsKey(topic);
    }

    private Map<String, SeverityFieldMapping> createSeverityFieldMappings(
            List<SeverityFieldMapping> mappings, EventTopicsMetaData eventTopicsMetaData) {

        Map<String, SeverityFieldMapping> results = new HashMap<>(mappings.size());
        for (SeverityFieldMapping mapping : mappings) {

            if (results.containsKey(mapping.getTopic())) {
                logger.warn("Multiple Syslog severity field mappings defined for {} topic", mapping.getTopic());
                continue;
            }

            if (!eventTopicsMetaData.containsTopic(mapping.getTopic())) {
                logger.warn("Syslog severity field mapping defined for unknown topic {}", mapping.getTopic());
                continue;
            }

            JsonValue auditEventMetaData = eventTopicsMetaData.getSchema(mapping.getTopic());
            JsonValue auditEventSchema;
            try {
                auditEventSchema = getAuditEventSchema(auditEventMetaData);
            } catch (ResourceException e) {
                logger.warn(e.getMessage());
                continue;
            }
            Set<String> topicFieldPointers = generateJsonPointers(auditEventSchema);
            String mappedField = mapping.getField();
            if (mappedField != null && !mappedField.startsWith("/")) {
                mappedField = "/" + mappedField;
            }
            if (! topicFieldPointers.contains(mappedField)) {
                logger.warn("Syslog severity field mapping for topic {} references unknown field {}",
                        mapping.getTopic(), mapping.getField());
                continue;
            }

            results.put(mapping.getTopic(), mapping);
        }
        return results;
    }

    private Map<String, StructuredDataFormatter> createStructuredDataFormatters(
            String productName,
            EventTopicsMetaData eventTopicsMetaData,
            String dataFormatterClassName) {

        final Map<String, StructuredDataFormatter> results = new HashMap<>();
        for (String topic : eventTopicsMetaData.getTopics()) {
            JsonValue schema = eventTopicsMetaData.getSchema(topic);
            results.put(topic, instantiateStructuredDataFormatter(dataFormatterClassName, productName, topic, schema));
        }
        return results;
    }

    private StructuredDataFormatter instantiateStructuredDataFormatter(String className, String productName, String topic, JsonValue schema) {
        Class formatterClz;
        try {
            formatterClz = Class.forName(className);
            if (!StructuredDataFormatter.class.isAssignableFrom(formatterClz)) {
                throw new IllegalArgumentException("");
            }
            StructuredDataFormatter inst = (StructuredDataFormatter) formatterClz.newInstance();
            inst.initialize(productName, topic, schema);
            return inst;
        } catch (ClassNotFoundException e) {
            throw new IllegalArgumentException("Structured data formatter class cannot be found", e);
        } catch (InstantiationException | IllegalAccessException e) {
            throw new IllegalArgumentException("Failed to instantiate structured data formatter", e);
        }
    }

    private Severity getSeverityLevel(String topic, JsonValue auditEvent) {
        if (severityFieldMappings.containsKey(topic)) {
            SeverityFieldMapping severityFieldMapping = severityFieldMappings.get(topic);
            String severityField = severityFieldMapping.getField();
            if (severityField != null && !severityField.startsWith("/")) {
                severityField = "/" + severityField;
            }
            JsonValue jsonValue = auditEvent.get(new JsonPointer(severityField));
            String severityValue = jsonValue == null ? null : jsonValue.asString();
            if (severityValue == null) {
                logger.debug("{} value not set; defaulting to INFORMATIONAL Syslog SEVERITY level", severityField);
            } else {
                try {
                    return Severity.valueOf(severityValue);
                } catch (IllegalArgumentException ex) {
                    logger.debug("{} is not a valid Syslog SEVERITY level; defaulting to INFORMATIONAL", severityValue);
                }
            }
        }
        // if no mapping was defined or the value wasn't a valid severity, default to INFORMATIONAL
        return Severity.INFORMATIONAL;
    }

    /**
     * Calculates the Syslog message PRI value.
     *
     * @see <a href="https://tools.ietf.org/html/rfc5424#section-6.2.1">RFC-5424 section 6.2.1</a>
     */
    private int calculatePriorityValue(Facility facility, Severity severityLevel) {
        return (facility.getCode() * 8) + severityLevel.getCode();
    }

    /**
     * Calculates the Syslog message HOSTNAME value.
     *
     * @see <a href="https://tools.ietf.org/html/rfc5424#section-6.2.4">RFC-5424 section 6.2.4</a>
     */
    private String getLocalHostName(LocalHostNameProvider localHostNameProvider) {
        String localHostName = localHostNameProvider.getLocalHostName();
        return localHostName != null ? localHostName : NIL_VALUE;
    }

    /**
     * Calculates the Syslog message APP-NAME value.
     *
     * @see <a href="https://tools.ietf.org/html/rfc5424#section-6.2.5">RFC-5424 section 6.2.5</a>
     */
    private String getProductName(ProductInfoProvider productInfoProvider) {
        String productName = productInfoProvider.getProductName();
        return productName != null ? productName : NIL_VALUE;
    }

}
