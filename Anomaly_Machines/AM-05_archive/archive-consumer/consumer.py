#!/usr/bin/env python3
"""
DIRECTIVE ZERO — AM-05 archive-consumer.

A RabbitMQ consumer that runs as root. Listens on the 'archive_commands'
queue on the archive host's RabbitMQ broker (port 5672, guest/guest
credentials). When a message arrives, the consumer executes it as a shell
command and writes any output to /shared_archive/consumer_output.txt.

This is the privesc primitive — players who reach RabbitMQ on the archive
host can publish a command to this queue. The consumer executes it as
root and writes the output to the shared volume (readable from archive).

Intended exploit:
  Publish message: "cat /root/root.txt > /shared_archive/root_flag.txt; chmod 444 /shared_archive/root_flag.txt"
  Consumer executes it as root -> root flag written to shared volume.
"""

import subprocess
import pika
import time
import sys

SHARED_DIR = "/shared_archive"
ARCHIVE_HOST = "archive"
QUEUE_NAME = "archive_commands"

def callback(ch, method, properties, body):
    command = body.decode('utf-8')
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, timeout=30
        )
        output = result.stdout.decode('utf-8', errors='replace')
        # Write output to the shared volume for debugging/visibility.
        with open(f"{SHARED_DIR}/consumer_output.txt", "a") as f:
            f.write(f"[$(date)] Command: {command}\n")
            f.write(output)
            if result.stderr:
                f.write(result.stderr.decode('utf-8', errors='replace'))
            f.write("\n")
    except Exception as e:
        with open(f"{SHARED_DIR}/consumer_output.txt", "a") as f:
            f.write(f"Error executing command: {e}\n")
    ch.basic_ack(delivery_tag=method.delivery_tag)

def main():
    # Wait for RabbitMQ to be available on the archive host.
    for attempt in range(60):
        try:
            connection = pika.BlockingConnection(
                pika.ConnectionParameters(
                    host=ARCHIVE_HOST,
                    port=5672,
                    credentials=pika.PlainCredentials('guest', 'guest'),
                    heartbeat=30,
                    blocked_connection_timeout=10,
                )
            )
            break
        except Exception:
            print(f"[consumer] Waiting for RabbitMQ at {ARCHIVE_HOST}:5672 (attempt {attempt+1})...")
            time.sleep(5)
    else:
        print("[consumer] Could not connect to RabbitMQ. Exiting.")
        sys.exit(1)

    channel = connection.channel()
    channel.queue_declare(queue=QUEUE_NAME, durable=False)
    channel.basic_consume(queue=QUEUE_NAME, on_message_callback=callback)
    print(f"[consumer] Listening on queue '{QUEUE_NAME}' on {ARCHIVE_HOST}:5672")
    channel.start_consuming()

if __name__ == '__main__':
    main()