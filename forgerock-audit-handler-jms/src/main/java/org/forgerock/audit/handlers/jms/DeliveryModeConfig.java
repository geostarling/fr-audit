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

import javax.jms.DeliveryMode;

/**
 * Configuration wrapper for JMS {@link DeliveryMode} persistence constants.
 */
public enum DeliveryModeConfig {
    PERSISTENT(DeliveryMode.PERSISTENT),
    NON_PERSISTENT(DeliveryMode.NON_PERSISTENT);

    private int mode;

    /**
     * Constructs the DeliveryModeConfig with the passed in mode.
     *
     * @param mode the configuration setting for this instance.
     * @see DeliveryMode
     */
    DeliveryModeConfig(int mode) {
        this.mode = mode;
    }

    /**
     * Returns the DeliveryMode value for this configuration.
     *
     * @return the DeliveryMode value for this configuration
     * @see DeliveryMode
     */
    public int getMode() {
        return mode;
    }
}
