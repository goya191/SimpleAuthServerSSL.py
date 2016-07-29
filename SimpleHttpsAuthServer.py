import BaseHTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
import sys
import os
import base64
import ssl
import SocketServer

key = ""
CERTFILE_PATH = "/root/server.pem"

class AuthHandler(SimpleHTTPRequestHandler):
    ''' Main class to present webpages and authentication. '''
    def do_HEAD(self):
        print "send header"
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        print "send header"
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        global key
        ''' Present frontpage with user authentication. '''
        if self.headers.getheader('Authorization') == None:
            self.do_AUTHHEAD()
            self.wfile.write('no auth header received')
            pass
        elif self.headers.getheader('Authorization') == 'Basic '+key:
            SimpleHTTPRequestHandler.do_GET(self)
            pass
        else:
            self.do_AUTHHEAD()
            self.wfile.write(self.headers.getheader('Authorization'))
            self.wfile.write('not authenticated')
            pass

def serve_https(https_port=80, HandlerClass = AuthHandler,
         ServerClass = BaseHTTPServer.HTTPServer):
    httpd = SocketServer.TCPServer(("", PORT), HandlerClass)
    httpd.socket = ssl.wrap_socket (httpd.socket, certfile=CERTFILE_PATH, server_side=True)

    sa = httpd.socket.getsockname()
    print "Serving HTTP on", sa[0], "port", sa[1], "..."
    httpd.serve_forever()

if __name__ == '__main__':
    if len(sys.argv)<3:
        print "usage SimpleAuthServer.py [port] [username:password]"
        sys.exit()

	https_port = int(sys.argv[1])
	key = base64.b64encode(sys.argv[2])

	if len(sys.argv) == 4:
		change_dir = sys.argv[3]
		print "Changing dir to {cd}".format(cd=change_dir)
		os.chdir(change_dir)

    serve_https(https_port)

