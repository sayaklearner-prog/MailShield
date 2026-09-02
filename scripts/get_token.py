#!/usr/bin/env python3
"""
MailShield — Instant Gmail OAuth Token Generator
Connects directly to Google OAuth using a local loopback server (zero redirect errors).
"""

import http.server
import json
import socketserver
import urllib.parse
import urllib.request
import webbrowser
import os
import sys

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

if not CLIENT_ID or not CLIENT_SECRET:
    # Attempt to load from local .env
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("GOOGLE_CLIENT_ID=") and not CLIENT_ID:
                    CLIENT_ID = line.split("=", 1)[1].strip("\"'")
                elif line.startswith("GOOGLE_CLIENT_SECRET=") and not CLIENT_SECRET:
                    CLIENT_SECRET = line.split("=", 1)[1].strip("\"'")


PORT = 8089
REDIRECT_URI = f"http://localhost:{PORT}/callback"
SCOPE = "openid email profile https://www.googleapis.com/auth/gmail.readonly"

auth_code = None

class OAuthHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        global auth_code
        url_parsed = urllib.parse.urlparse(self.path)
        if url_parsed.path == "/callback":
            query_params = urllib.parse.parse_qs(url_parsed.query)
            if "code" in query_params:
                auth_code = query_params["code"][0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                html = """
                <html>
                <body style="font-family: monospace; background: #0b0f19; color: #38bdf8; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh;">
                    <div style="padding: 30px; border: 1px solid #0284c7; border-radius: 12px; background: #030712; text-align: center;">
                        <h2 style="color: #4ade80;">✔ Google Authentication Successful!</h2>
                        <p style="color: #94a3b8;">You can close this tab and return to your terminal.</p>
                    </div>
                </body>
                </html>
                """
                self.wfile.write(html.encode("utf-8"))
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Authentication failed.")
        else:
            self.send_response(404)
            self.end_headers()

def run_oauth():
    global auth_code
    print("=" * 65)
    print("  🛡️  MailShield — Instant Gmail Token Authenticator")
    print("=" * 65)
    
    # Check if redirect URI is in Google Cloud Console
    auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={urllib.parse.quote(CLIENT_ID)}&"
        f"redirect_uri={urllib.parse.quote(REDIRECT_URI)}&"
        f"response_type=code&"
        f"scope={urllib.parse.quote(SCOPE)}&"
        f"access_type=offline&"
        f"prompt=consent"
    )

    print(f"\n1. Starting temporary local auth receiver on http://localhost:{PORT}...")
    print(f"2. Opening Google Authorization page in your default browser...\n")
    print(f"👉 If the browser doesn't open automatically, click this link:\n{auth_url}\n")
    
    try:
        webbrowser.open(auth_url)
    except Exception:
        pass

    with socketserver.TCPServer(("", PORT), OAuthHandler) as httpd:
        httpd.handle_request()

    if not auth_code:
        print("❌ Failed to receive authorization code.")
        sys.exit(1)

    print("\n3. Exchanging authorization code for Google Access Token...")
    token_url = "https://oauth2.googleapis.com/token"
    data = urllib.parse.urlencode({
        "code": auth_code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
    }).encode("utf-8")

    req = urllib.request.Request(token_url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req) as resp:
            token_json = json.loads(resp.read().decode("utf-8"))
            access_token = token_json.get("access_token")
            refresh_token = token_json.get("refresh_token")

            print("\n" + "=" * 65)
            print("  🎉 GOOGLE ACCESS TOKEN GENERATED SUCCESSFULLY!")
            print("=" * 65)
            print(f"\nCopy this Access Token:\n\n{access_token}\n")
            print("=" * 65)
            print("👉 Next Step:")
            print("1. Open your live app: https://mail-shield-6geskx2se-sayaklearner-progs-projects.vercel.app/settings")
            print("2. Paste this token into 'Option 2: Direct Token Connection'")
            print("3. Click 'Verify & Connect Mailbox' — and your live emails will load!")
            print("=" * 65)

    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8")
        print(f"\n❌ Error during token exchange: {err_msg}")
        if "redirect_uri_mismatch" in err_msg:
            print(f"\n👉 To fix this, add '{REDIRECT_URI}' to 'Authorized redirect URIs' in Google Cloud Console:")
            print("https://console.cloud.google.com/apis/credentials")

if __name__ == "__main__":
    run_oauth()
