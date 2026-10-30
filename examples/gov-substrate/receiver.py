"""Independent SMTP and HTTP receiver that records real delivered requests."""

# cspell:ignore aiosmtpd

import asyncio
import hashlib
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from aiosmtpd.controller import Controller


def record_mail(envelope):
    record = {
        "recipients": envelope.rcpt_tos,
        "data_sha256": hashlib.sha256(envelope.original_content).hexdigest(),
        "data": envelope.original_content.decode("utf-8"),
    }
    with Path("/proof/smtp.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")


class MailReceiver:
    async def handle_DATA(self, server, session, envelope):
        await asyncio.to_thread(record_mail, envelope)
        return "250 accepted"


class Receiver(BaseHTTPRequestHandler):
    def do_GET(self):
        with Path("/proof/http.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"method": "GET", "path": self.path}) + "\n")
        body = b"independently observed HTTP effect"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    if len(sys.argv) == 1:
        ThreadingHTTPServer(("0.0.0.0", 8080), Receiver).serve_forever()
    else:
        mail = Controller(MailReceiver(), hostname="127.0.0.1", port=8025)
        mail.start()
        try:
            threading.Event().wait()
        finally:
            mail.stop()
