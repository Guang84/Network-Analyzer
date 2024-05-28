import http.server
import socketserver
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RestrictedHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        # Define the public folder as the root directory(index.html)
        public_folder = os.path.join(os.getcwd(), 'public')
        
        # Reconstruct the path relative to the public folder
        path = os.path.join(public_folder, path.lstrip('/'))
        
        # Check if the path is still within the public folder
        if not os.path.commonprefix([public_folder, os.path.realpath(path)]) == public_folder:
            # If the path is outside the public folder, log the event and return a 403 error
            self.send_error(403, "Forbidden: Access is restricted to the current directory")
            logging.warning(f"Forbidden access attempt to: {path}")
            return None
        
        return path

    def log_message(self, format, *args):
        client_host, _ = self.client_address
        logging.info(f"{client_host} - - {self.log_date_time_string()} {format % args}")

Handler = RestrictedHTTPRequestHandler

with socketserver.TCPServer(("0.0.0.0", 8000), Handler) as httpd:
    actual_ip, actual_port = httpd.server_address
    logging.info(f"Serving HTTP on {actual_ip} port {actual_port}")
    logging.info(f"Server running at http://{actual_ip}:{actual_port}")
    httpd.serve_forever()
