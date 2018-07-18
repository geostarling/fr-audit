package org.forgerock.audit.handlers.syslog.formatters;


import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.util.Reject;

import java.util.HashSet;
import java.util.Set;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableSet;
import static org.forgerock.audit.events.AuditEventBuilder.EVENT_NAME;
import static org.forgerock.audit.events.AuditEventBuilder.TIMESTAMP;
import static org.forgerock.audit.events.AuditEventHelper.getAuditEventSchema;
import static org.forgerock.audit.events.AuditEventHelper.jsonPointerToDotNotation;
import static org.forgerock.audit.util.JsonSchemaUtils.generateJsonPointers;
import static org.forgerock.audit.util.JsonValueUtils.extractValueAsString;


/**
 * Responsible for formatting an {@link AuditEvent}'s JSON representation as an RFC-5424 compliant SD-ELEMENT.
 * <p>
 * Objects are immutable and can therefore be freely shared across threads without synchronization.
 *
 * @see <a href="https://tools.ietf.org/html/rfc5424#section-6.3">RFC-5424 section 6.3</a>
 */
public class StandardStructuredDataFormatter implements StructuredDataFormatter {

    protected String productName;
    protected String topic;
    protected JsonValue auditEventMetadata;

    /**
     * The set of audit event fields that should not be copied to structured-data.
     */
    private static final Set<String> IGNORED_FIELDS = unmodifiableSet(
            new HashSet<>(asList("_id", TIMESTAMP, EVENT_NAME)));

    private String id;
    private Set<String> fieldNames;


    private static final String FORGEROCK_IANA_ENTERPRISE_ID = "36733";

    /**
     * Initialize a new StructuredDataFormatter.
     *
     * @param productName        Name of the ForgeRock product in which the {@link AuditService}
     *                           is executing; the SD-ID of each STRUCTURED-DATA element is derived from the
     *                           <code>productName</code> and <code>topic</code>.
     * @param topic              Coarse-grained categorisation of the types of audit events that this formatter handles;
     *                           the SD-ID of each STRUCTURED-DATA element is derived from the <code>productName</code>
     *                           and <code>topic</code>.
     * @param auditEventMetaData Schema and additional meta-data for the audit event topic.
     */
    @Override
    public void initialize(String productName, String topic, JsonValue auditEventMetaData) {
        Reject.ifNull(productName, "Product name required.");
        Reject.ifNull(topic, "Audit event topic name required.");

        JsonValue auditEventSchema;
        try {
            auditEventSchema = getAuditEventSchema(auditEventMetaData);
        } catch (ResourceException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }

        id = topic + "." + productName + "@" + FORGEROCK_IANA_ENTERPRISE_ID;
        fieldNames = unmodifiableSet(generateJsonPointers(auditEventSchema));
    }


    /**
     * Translate the provided <code>auditEvent</code> to an RFC-5424 compliant SD-ELEMENT.
     *
     * @param auditEvent The audit event to be formatted.
     * @return an RFC-5424 compliant SD-ELEMENT.
     */
    @Override
    public String format(JsonValue auditEvent) {

        StringBuilder sd = new StringBuilder();

        sd.append("[");
        sd.append(id);
        for (String fieldName : fieldNames) {
            String formattedName = formatParamName(fieldName);
            if (IGNORED_FIELDS.contains(formattedName)) {
                continue;
            }
            sd.append(" ");
            sd.append(formattedName);
            sd.append("=\"");
            sd.append(formatParamValue(extractValueAsString(auditEvent, fieldName)));
            sd.append("\"");
        }
        sd.append("]");

        return sd.toString();
    }

    private String formatParamName(String name) {
        return jsonPointerToDotNotation(name);
    }

    private String formatParamValue(String value) {
        if (value == null) {
            return "";
        } else {
            return value.replaceAll("[\\\\\"\\]]", "\\\\$0");
        }
    }
}