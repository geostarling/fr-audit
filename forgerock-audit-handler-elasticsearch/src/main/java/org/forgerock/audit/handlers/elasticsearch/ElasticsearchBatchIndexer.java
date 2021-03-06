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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.forgerock.json.JsonValue;
import org.forgerock.util.Reject;
import org.forgerock.util.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.lang.Math.max;

/**
 * Uses Elasticsearch Bulk API to index audit events in batches.
 */
class ElasticsearchBatchIndexer {

    private static final Logger logger = LoggerFactory.getLogger(ElasticsearchAuditEventHandler.class);

    private static final int MIN_QUEUE_SIZE = 10000;
    private static final int MIN_BATCH_SIZE = 500;
    private static final int MIN_PER_EVENT_PAYLOAD_SIZE = 32;
    private static final Duration DEFAULT_WRITE_INTERVAL = new Duration(1L, TimeUnit.SECONDS);

    private final BlockingQueue<BatchEntry> queue;
    private final ScheduledExecutorService scheduler;
    private final QueueConsumer queueConsumer;
    private final Duration writeInterval;

    /**
     * Creates a {@link ElasticsearchBatchIndexer}. For arguments with minimum values, the minimum will be used
     * without warning if the provided value is lower than that minimum.
     *
     * @param capacity Fixed queue size (min. is 10000)
     * @param writeInterval Interval to read up to {@code maxBatchedEvents} from the queue,
     * or {@code null} (default 1 second)
     * @param maxBatchedEvents Batch size (min. is 500)
     * @param averagePerEventPayloadSize Average number of characters, per event, in a batch payload (min. is 32)
     * @param autoFlush {@code true} when data in queue should always be flushed on shutdown and {@code false} when
     * it is acceptable to drop events in the queue
     * @param eventHandler Batch audit event handler
     */
    public ElasticsearchBatchIndexer(final int capacity, final Duration writeInterval, final int maxBatchedEvents,
            final int averagePerEventPayloadSize, final boolean autoFlush,
            final ElasticsearchBatchAuditEventHandler eventHandler) {
        queue = new ArrayBlockingQueue<>(max(capacity, MIN_QUEUE_SIZE));
        scheduler = Executors.newScheduledThreadPool(1);
        queueConsumer = new QueueConsumer(
                max(maxBatchedEvents, MIN_BATCH_SIZE),
                max(averagePerEventPayloadSize, MIN_PER_EVENT_PAYLOAD_SIZE),
                autoFlush, queue, scheduler, Reject.checkNotNull(eventHandler));
        this.writeInterval = writeInterval == null || writeInterval.getValue() <= 0 ?
                DEFAULT_WRITE_INTERVAL : writeInterval;
    }

    /**
     * Starts periodically sending batch data to Elasticsearch.
     */
    public void startup() {
        scheduler.scheduleAtFixedRate(queueConsumer, 0, writeInterval.to(TimeUnit.MILLISECONDS), TimeUnit.MILLISECONDS);
    }

    /**
     * Stops sending batch data to Elasticsearch, and awaits termination of pending queue tasks when {@code autoFlush}
     * is enabled.
     */
    public void shutdown() {
        if (!scheduler.isShutdown()) {
            queueConsumer.shutdown();
        }
    }

    /**
     * Inserts the specified element at the tail of this queue if it is possible to do so immediately without
     * exceeding the queue's capacity, returning {@code true} upon success and {@code false} if this queue is full.
     *
     * @param topic Event topic
     * @param event Event payload to index, where {@code _id} field is the identifier
     * @return {@code true} if the element was added to this queue, else {@code false}
     */
    public boolean offer(final String topic, final JsonValue event) {
        return queue.offer(new BatchEntry(topic, event));
    }

    /**
     * A single audit-event batch entry.
     */
    private static class BatchEntry {

        private final String topic;
        private final JsonValue event;

        /**
         * Creates a new audit-event batch entry.
         *
         * @param topic Event topic
         * @param event Event JSON payload
         */
        public BatchEntry(final String topic, final JsonValue event) {
            this.topic = topic;
            this.event = event;
        }

        /**
         * Gets the event JSON payload.
         *
         * @return Event JSON payload
         */
        public JsonValue getEvent() {
            return event;
        }

        /**
         * Gets the event topic.
         *
         * @return Event topic
         */
        public String getTopic() {
            return topic;
        }
    }

    /**
     * Consumer of the audit-event batch queue, which can be scheduled to run periodically. This class is not
     * thread-safe, and is intended to be run by a single thread.
     */
    private static class QueueConsumer implements Runnable {

        private final int maxBatchedEvents;
        private final boolean flushOnShutdown;
        private final BlockingQueue<BatchEntry> queue;
        private final List<BatchEntry> batch;
        private final StringBuilder payload;
        private final ElasticsearchBatchAuditEventHandler eventHandler;
        private final ScheduledExecutorService scheduler;

        private volatile boolean shutdown;

        /**
         * Creates a {@code QueueConsumer}.
         *
         * @param maxBatchedEvents Batch size
         * @param averagePerEventPayloadSize Average number of characters, per event, in a batch payload
         * @param flushOnShutdown When {@code true}, the queue will be flushed on shutdown and when {@code false},
         * items in the queue will be dropped
         * @param queue Audit-event queue
         * @param scheduler This runnable's scheduler
         * @param eventHandler Batch audit event handler
         */
        public QueueConsumer(final int maxBatchedEvents, final int averagePerEventPayloadSize,
                final boolean flushOnShutdown, final BlockingQueue<BatchEntry> queue,
                final ScheduledExecutorService scheduler, final ElasticsearchBatchAuditEventHandler eventHandler) {
            this.queue = queue;
            this.flushOnShutdown = flushOnShutdown;
            this.scheduler = scheduler;
            this.eventHandler = eventHandler;
            this.maxBatchedEvents = maxBatchedEvents;
            batch = new ArrayList<>(maxBatchedEvents);
            payload = new StringBuilder(maxBatchedEvents * averagePerEventPayloadSize);
        }

        /**
         * Informs queue consumer that shutdown has been triggered, and when {@code flushOnShutdown} is enabled,
         * blocks until all events have been flushed from the queue.
         */
        public void shutdown() {
            if (!shutdown) {
                shutdown = true;

                if (flushOnShutdown) {
                    // flush requested, so block in an non-cancelable way
                    boolean interrupted = false;
                    while (!scheduler.isTerminated()) {
                        try {
                            scheduler.awaitTermination(1L, TimeUnit.MINUTES);
                        } catch (InterruptedException e) {
                            interrupted = true;
                        }
                    }
                    if (interrupted) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
        }

        /**
         * Performs batch operation.
         */
        private void batch() {
            queue.drainTo(batch, maxBatchedEvents);
            if (!batch.isEmpty()) {
                try {
                    // add to batch
                    for (final BatchEntry entry : batch) {
                        try {
                            eventHandler.addToBatch(entry.getTopic(), entry.getEvent(), payload);
                        } catch (Exception e) {
                            logger.error("addToBatch failed", e);
                        }
                    }

                    // send batch
                    if (payload.length() != 0) {
                        try {
                            eventHandler.publishBatch(payload.toString());
                        } catch (Exception e) {
                            logger.error("publishBatch failed", e);
                        }
                    }
                } finally {
                    // clear buffers to prepare for next batch
                    batch.clear();
                    payload.setLength(0);
                }
            }
        }

        @Override
        public void run() {
            if (shutdown) {
                // we shutdown this runnable's scheduler here, so that we can guarantee that flush will proceed
                scheduler.shutdown();
                if (flushOnShutdown) {
                    // flush queue
                    while (!queue.isEmpty()) {
                        batch();
                    }
                }
            }

            // normal run of batch operation
            batch();
        }
    }

}
