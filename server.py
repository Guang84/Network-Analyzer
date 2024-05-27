import http.server
import socketserver
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RestrictedHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        path = super().translate_path(path)
        if not path.startswith(os.getcwd()):
            # If the path is outside the current directory, log the event and return a 403 error
            self.send_error(403, "Forbidden: Access is restricted to the current directory")
            logging.warning(f"Forbidden access attempt to: {path}")
            return None
        return path

    def log_message(self, format, *args):
        # Customize log messages to include client's IP address
        client_host, _ = self.client_address
        logging.info(f"{client_host} - - {self.log_date_time_string()} {format % args}")

Handler = RestrictedHTTPRequestHandler

with socketserver.TCPServer(("0.0.0.0", 8000), Handler) as httpd:
    actual_ip, actual_port = httpd.server_address
    logging.info(f"Serving HTTP on {actual_ip} port {actual_port}")
    logging.info(f"Server running at http://{actual_ip}:{actual_port}")
    httpd.serve_forever()
