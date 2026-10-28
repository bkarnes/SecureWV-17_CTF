#!/usr/bin/env python3
"""
DIRECTIVE ZERO — AM-05 The Archive document service.

A Flask web application that serves as the QUORUM "Archive Document Portal."
Citizens upload document text for rendering and archival.

VULNERABILITY: Server-Side Template Injection (SSTI) in the /upload endpoint.
The app calls render_template_string() on user-supplied content, allowing
Jinja2 template directives ({{ }}) to execute arbitrary Python code.

Exploit:
  POST /upload with content={{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
"""

import os
from flask import Flask, request, render_template_string, render_template

app = Flask(__name__)

ARCHIVE_DOCS_DIR = os.path.join(os.path.dirname(__file__), 'archived_documents')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    content = request.form.get('content', '')
    # VULNERABLE — render_template_string on user-supplied content = SSTI.
    # The app is supposed to render simple text documents, but using
    # render_template_string means any Jinja2 directives in the content
    # are evaluated as Python code.
    try:
        rendered = render_template_string(content)
    except Exception as e:
        rendered = f"Document processing error: {e}"
    return render_template('result.html', output=rendered)

@app.route('/documents')
def documents():
    """List archived documents (lore discovery vector)."""
    docs = []
    if os.path.isdir(ARCHIVE_DOCS_DIR):
        docs = sorted(os.listdir(ARCHIVE_DOCS_DIR))
    return render_template('documents.html', docs=docs)

@app.route('/documents/<filename>')
def view_document(filename):
    """View an archived document."""
    filepath = os.path.join(ARCHIVE_DOCS_DIR, filename)
    if os.path.isfile(filepath):
        with open(filepath, 'r') as f:
            content = f.read()
        return render_template('view_document.html',
                               filename=filename, content=content)
    return "Document not found.", 404

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=8443,
        ssl_context=('/opt/archive/certs/cert.pem', '/opt/archive/certs/key.pem')
    )