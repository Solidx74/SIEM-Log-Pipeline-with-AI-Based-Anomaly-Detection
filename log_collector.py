#!/usr/bin/env python3
"""
Log receiver server that writes received logs to a fixed log file.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import argparse
import logging
import os
from datetime import datetime

# Configure logging for the server itself
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s [SERVER] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class LogReceiver(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/logs':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                # Data can be plain text or JSON; we assume plain text for simplicity
                log_line = post_data.decode('utf-8').strip()
                source_host = self.client_address[0]
                
                logger.info(f"Received log from {source_host}")
                
                # Write log to fixed file (we'll use a fixed name for simplicity)
                filename = "logs/raw_logs.log"
                with open(filename, 'a', encoding='utf-8') as f:
                    f.write(log_line + '\n')
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status": "received"}')
                
            except Exception as e:
                logger.error(f"Error processing request: {e}")
                self.send_response(400)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        # Suppress default HTTP logging
        pass

def main():
    parser = argparse.ArgumentParser(description='Log receiver server')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port to listen on')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    args = parser.parse_args()
    
    os.makedirs('logs', exist_ok=True)
    server = HTTPServer((args.host, args.port), LogReceiver)
    logger.info(f"HTTP server listening on {args.host}:{args.port}")
    logger.info("Logs will be written to logs/raw_logs.log")
    logger.info("Press Ctrl+C to stop")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped")

if __name__ == "__main__":
    main()