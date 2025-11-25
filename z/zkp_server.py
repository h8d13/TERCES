#!/usr/bin/env python3
"""
Simple localhost ZKP authentication server for testing.
Client can authenticate using ZKP proofs and get session tokens.
"""

import sys
import os
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'z'))
from gnilux.nzkp import PrimeTimeTZKP

# In-memory storage
users = {}  # user_id -> public_key
sessions = {}  # token -> session_data

class ZKPAuthHandler(BaseHTTPRequestHandler):
    def _send_json(self, code, data):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length).decode()
        path = urlparse(self.path).path

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON"})
            return

        if path == '/register':
            self.handle_register(data)
        elif path == '/login':
            self.handle_login(data)
        elif path == '/verify':
            self.handle_verify(data)
        else:
            self._send_json(404, {"error": "Not found"})

    def handle_register(self, data):
        """Register a user's public key"""
        user_id = data.get('user_id')
        public_key = data.get('public_key')
        bits = data.get('bits', 2048)

        if not user_id or not public_key:
            self._send_json(400, {"error": "Missing user_id or public_key"})
            return

        users[user_id] = {
            'public_key': int(public_key),
            'bits': bits
        }

        print(f"[REGISTER] User: {user_id}, Public Key: {str(public_key)[:20]}...")
        self._send_json(200, {
            "status": "registered",
            "user_id": user_id
        })

    def handle_login(self, data):
        """Verify proof and issue session token"""
        user_id = data.get('user_id')
        proof = data.get('proof')

        if not user_id or not proof:
            self._send_json(400, {"error": "Missing user_id or proof"})
            return

        if user_id not in users:
            self._send_json(404, {"error": "User not registered"})
            return

        user = users[user_id]
        zkp = PrimeTimeTZKP(user['bits'])

        # Verify the proof
        valid, message = zkp.verify_proof(user['public_key'], proof)
        if not valid:
            print(f"[LOGIN FAILED] User: {user_id}, Reason: {message}")
            self._send_json(401, {"error": f"Authentication failed: {message}"})
            return

        # Issue session token
        session = zkp.issue_session_token(proof, user_id)
        token = session['token']

        # Store session server-side
        sessions[token] = session

        print(f"[LOGIN SUCCESS] User: {user_id}, Token: {token[:20]}...")
        self._send_json(200, {
            "status": "authenticated",
            "token": token,
            "message": "Session token issued"
        })

    def handle_verify(self, data):
        """Verify a session token"""
        token = data.get('token')

        if not token:
            self._send_json(400, {"error": "Missing token"})
            return

        if token not in sessions:
            print(f"[VERIFY FAILED] Token not found: {token[:20]}...")
            self._send_json(401, {"error": "Invalid or expired token"})
            return

        session = sessions[token]
        user_id = session['user_id']
        user = users[user_id]

        zkp = PrimeTimeTZKP(user['bits'])

        # Verify token against stored session
        valid, message = zkp.verify_session_token(
            user['public_key'],
            token,
            session['proof'],
            session['nonce'],
            session['user_id']
        )

        if valid:
            print(f"[VERIFY SUCCESS] User: {user_id}, Token: {token[:20]}...")
            self._send_json(200, {
                "status": "valid",
                "user_id": user_id,
                "message": message
            })
        else:
            print(f"[VERIFY FAILED] User: {user_id}, Reason: {message}")
            self._send_json(401, {
                "status": "invalid",
                "message": message
            })

    def log_message(self, format, *args):
        # Suppress default HTTP logs
        pass


def main():
    port = 8080
    server = HTTPServer(('localhost', port), ZKPAuthHandler)
    print(f"ZKP Auth Server running on http://localhost:{port}")
    print()
    print("Endpoints:")
    print("  POST /register  - Register public key")
    print("  POST /login     - Authenticate and get session token")
    print("  POST /verify    - Verify session token")
    print()
    print("Ready for client requests...")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.shutdown()


if __name__ == '__main__':
    main()
