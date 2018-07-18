package org.forgerock.audit.handlers.syslog.formatters;

import org.forgerock.json.JsonValue;

public interface StructuredDataFormatter {

    void initialize(String productName, String topic, JsonValue auditEventMetaData);

    String format(JsonValue auditEvent);

}
