# DIRECTIVE ZERO — AM-05: The Archive (MQ consumer — internal host)
# Hard. The isolated consumer that runs as root.
#
# Connects to the archive host's RabbitMQ on port 5672, listens on the
# 'archive_commands' queue, and executes commands from messages as root.
# Writes output to /shared_archive/ (a Docker volume shared with archive).
#
# This is the privesc target — players who reach RabbitMQ on archive can
# publish a command that this consumer executes as root, writing the root
# flag to the shared volume.

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 \
      python3-pip \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir --break-system-packages pika

COPY consumer.py /opt/consumer/consumer.py
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]