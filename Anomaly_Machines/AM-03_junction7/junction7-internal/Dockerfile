# DIRECTIVE ZERO — AM-03: Network Junction 7 (internal host)
# Medium. The isolated internal service node — only reachable via pivot
# through the public host (junction7).
#
# Exploit chain (reproduced from the WinterMute Neuromancer shape):
#   1. Reached via pivot from junction7 (socat or direct curl/nc from shell)
#   2. Port 8080: Apache Tomcat 9 + Struts 2.3.15.1 showcase (S2-048 RCE)
#   3. Port 34483: OpenSSH (for TTY upgrade after RCE)
#   4. RCE as `compliance` user -> internal user flag
#   5. Privesc: root-run cron job executes world-writable script -> root
#
# Flags are injected via env vars at runtime (never baked in):
#   AM03_INTERNAL_USER_FLAG, AM03_INTERNAL_ROOT_FLAG

FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64 \
    CATALINA_HOME=/usr/share/tomcat9 \
    CATALINA_BASE=/var/lib/tomcat9

# ── Base packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      openjdk-11-jre-headless \
      tomcat9 \
      openssh-server \
      cron \
      net-tools \
      iputils-ping \
      curl \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Deploy the Struts 2.3.15.1 showcase WAR (S2-048) ────────────────────────
COPY struts/struts2-showcase-2.3.15.1.war \
     /var/lib/tomcat9/webapps/struts2_2.3.15.1-showcase.war



# ── compliance user (the RCE lands here, owns the internal user flag) ──────
RUN useradd -m -s /bin/bash compliance \
 && mkdir -p /run/sshd

# ── Cron privesc artifact ──────────────────────────────────────────────────
COPY cron/system_check.sh /opt/junction/system_check.sh
RUN chmod 777 /opt/junction/system_check.sh

# ── SSH config (non-standard port 34483, matching the source box) ──────────
COPY configs/sshd_config /etc/ssh/sshd_config

# ── Tomcat config: listen on 8080 ──────────────────────────────────────────
# Debian's tomcat9 listens on 8080 by default — no change needed.

# ── Hostname + MOTD retheme ────────────────────────────────────────────────
RUN echo "junction7-internal" > /etc/hostname \
 && printf '%s\n' \
    '  ┌──────────────────────────────────────────────────────────────┐' \
    '  │  QUORUM CONSTRUCT — JUNCTION 7 INTERNAL NODE           AM-03 │' \
    '  │  "This node does not appear in any official Construct map."  │' \
    '  │  "Its existence has not been confirmed. It has not been      │' \
    '  │   denied either. Both options are under review."             │' \
    '  └──────────────────────────────────────────────────────────────┘' \
    > /etc/motd

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 8080 34483

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]