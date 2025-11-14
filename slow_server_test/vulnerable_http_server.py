from http.server import BaseHTTPRequestHandler, HTTPServer
import time


class VulnerableHTTPRequestHandler(BaseHTTPRequestHandler):
    counter = 0

    def do_GET(self):
        time.sleep(2)  # Simulate Processing Delay

        type(self).counter += 1
        current = type(self).counter

        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

        message = f'Log count {current}'
        self.wfile.write(message + st.encode('utf-8'))


def run(server_class=HTTPServer, handler_class=VulnerableHTTPRequestHandler, port=8000) -> None:
    server_address = ('*my own local ipv4 in this case*', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting httpd on port {port} ...")
    httpd.serve_forever()


if __name__ == "__main__":
    run()
