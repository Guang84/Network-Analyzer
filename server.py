import http.server
import socketserver
import os

class RestrictedHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.path = '/index.html'  # Serve index.html by default

        # Call the parent class method to serve the requested file
        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def translate_path(self, path):
        # Get the requested path and normalize it
        path = super().translate_path(path)
        # Ensure that the requested path is within the current directory
        if not path.startswith(os.getcwd()):
            # If the path is outside the current directory, return a 403 error
            self.send_error(403, "Forbidden: Access is restricted to the current directory")
            return None
        return path

Handler = RestrictedHTTPRequestHandler

# Let the operating system choose an available port by passing 0
with socketserver.TCPServer(("0.0.0.0", 8000), Handler) as httpd:  # Change the port number as needed
    actual_ip, actual_port = httpd.server_address
    print("Network Analyzer")
    print("Version: 2024.06.24")
    print("Serving NA webpage on", actual_ip, "port", actual_port)
    print("Click the link below to access the server:")
    print(f"http://{actual_ip}:{actual_port}/")
    httpd.serve_forever()
