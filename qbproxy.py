from http.server import HTTPServer, BaseHTTPRequestHandler
from http.client import HTTPSConnection, HTTPConnection
from socketserver import ThreadingMixIn
from zlib import decompress, MAX_WBITS
from ssl import _create_unverified_context, wrap_socket, PROTOCOL_TLS_SERVER, SSLContext
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
from os import path, makedirs
from subprocess import Popen, PIPE
from argparse import ArgumentParser
from functools import partial

import threading
import traceback

from warnings import filterwarnings
filterwarnings(action='ignore', module='.*OpenSSL.*')
filterwarnings(action='ignore', module='.*ssl.*')

def gen_keys():

	#openssl genrsa -out root_ca.key 2048
	#openssl genrsa -out cert.key 2048
	#openssl req -new -x509 -days 3650 -key root_ca.key -subj "/CN=QBProxy" -out root_ca.crt

	root_ca_key = 'root_ca.key'
	root_ca_cert = 'root_ca.crt'
	cert_key = 'cert.key'

	now = datetime.now()

	root_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
		backend=default_backend()
	)

	root_cert = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"QBProxy")])).\
	issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"QBProxy")])).\
	public_key(root_key.public_key()).\
	serial_number(x509.random_serial_number()).\
	not_valid_before(now).\
	not_valid_after(now + timedelta(days=365)).\
	add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True,).\
	add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False,).\
	add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False,).\
	sign(root_key, hashes.SHA256(), default_backend())

	cert_key_ = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
		backend=default_backend()
	)

	with open(root_ca_key, 'wb') as f:
		f.write(root_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption(),
		))

	with open(root_ca_cert, 'wb') as f:
		f.write(root_cert.public_bytes(
		encoding=serialization.Encoding.PEM))

	with open(cert_key, 'wb') as f:
		f.write(cert_key_.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption(),
		))

def run_server(parsed_args):
	class Proxy(BaseHTTPRequestHandler):
		hostname = None
		port = None

		root_ca_key = 'root_ca.key'
		root_ca_cert = 'root_ca.crt'
		cert_key = 'cert.key'

		root_ca_cert_content = None
		root_ca_key_content = None
		private_key_content = None

		with open(cert_key, 'rb') as file:
			private_key_content = load_pem_private_key(file.read(), None, default_backend())

		with open(root_ca_cert, 'rb') as file:
			root_ca_cert_content = x509.load_pem_x509_certificate(file.read(), default_backend())

		with open(root_ca_key, 'rb') as file:
			root_ca_key_content = load_pem_private_key(file.read(), None, default_backend())

		lock = threading.Lock()


		def __init__(self, block_website, block_content, *args, **kwargs):
			self.block_website = block_website
			self.block_content = block_content
			super().__init__(*args, **kwargs)

		def do_GET(self):
			path = None
			server = None

			if self.path == 'http://cert.cert/':
				self.send_response(200, 'Connection Established')
				self.send_header('Content-Type', 'application/x-x509-ca-cert')
				self.send_header('Content-Length', len(self.root_ca_cert_content.public_bytes(serialization.Encoding.PEM)))
				self.send_header('Connection', 'close')
				self.end_headers()
				self.wfile.write(self.root_ca_cert_content.public_bytes(serialization.Encoding.PEM))
				return

			if self.port == '443':
				path = '{}{}{}'.format('https://',self.headers.get('Host'),self.path)
				server = HTTPSConnection(self.headers.get('Host'), context=_create_unverified_context())
			else:
				path = '{}{}{}'.format('http://',self.headers.get('Host'),self.path)
				server = HTTPConnection(self.headers.get('Host'))
			try:
				filter_headers = ['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailers','transfer-encoding','upgrade']
				data_in = self.rfile.read(int(self.headers.get('Content-Length', 0)))
				self.log_message('In \n\n%s\n\n%s',str(self.headers).strip(),data_in)
				server.request(self.command, path, data_in, self.headers)
				response = server.getresponse()
				response_raw = response.read()

				if self.block_content != None:
					if self.block_content in response_raw.decode('utf-8','ignore'):
						response_raw = b'Blocked\r\n'

				self.send_response(response.status)
				for header in response.getheaders():
					if header[0].lower() not in filter_headers:
						if header[0].lower() == 'content-length':
							temp = list(header)
							temp[1] = len(response_raw)
							header = tuple(temp)
						self.send_header(*header)
				self.end_headers()

				self.wfile.write(response_raw)
				self.wfile.flush()
				headers = "\n".join("{}={}".format(item[0],item[1]) for item in response.getheaders())
				if ('Content-Encoding', 'gzip') in response.getheaders():
					self.log_message('Out \n\n%s\n\n%s',headers,decompress(response_raw, MAX_WBITS | 16))
				else:
					self.log_message('Out \n\n%s\n\n%s',headers,response_raw)
			except Exception as e:
				print(traceback.format_exc())
				pass

		def do_CONNECT(self):

			self.hostname = self.path.split(':')[0]
			self.port = self.path.split(':')[1]

			if self.block_website != None:
				if self.hostname in self.block_website:
					self.log_message('Website is blacklisted %s',self.path)
					self.connection.close()
					return
				
			self.log_message('Website is whitelisted %s',self.path)

			self.send_response(200, 'Connection Established')
			self.end_headers()

			try:
				cert_file = "certs/{}.crt".format(self.hostname)
				with self.lock:
					if not path.isfile(cert_file):

						#Needed
						#subjectAltName=DNS:{},DNS:www.{}\nextendedKeyUsage=serverAuth,clientAuth

						# Generate a CSR
						csr_cert = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
						x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
						x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"WA"),
						x509.NameAttribute(NameOID.LOCALITY_NAME, u"Seattle"),
						x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"QBProxy"),
						x509.NameAttribute(NameOID.COMMON_NAME, self.hostname),])).sign(self.private_key_content, hashes.SHA256())

						# Sign the Cert
						now = datetime.now()
						cert = x509.CertificateBuilder().\
						subject_name(csr_cert.subject).\
						issuer_name(self.root_ca_cert_content.subject). \
						public_key(csr_cert.public_key()).\
						serial_number(x509.random_serial_number()).\
						not_valid_before(now).\
						not_valid_after(now + timedelta(days=2)).\
						add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), True).\
						add_extension(x509.SubjectAlternativeName([x509.DNSName(self.hostname),x509.DNSName('www.{}'.format(self.hostname))]), True).\
						sign(self.root_ca_key_content, hashes.SHA256())

						with open(cert_file, 'wb') as file:
							file.write(cert.public_bytes(serialization.Encoding.PEM))

				sslctx = SSLContext(PROTOCOL_TLS_SERVER)
				sslctx.check_hostname = False 
				sslctx.load_cert_chain(certfile=cert_file, keyfile=self.cert_key)
				self.connection = sslctx.wrap_socket(self.connection, server_side=True)

			except Exception as e:
				#print(traceback.format_exc())
				pass
			self.rfile = self.connection.makefile('rb', self.rbufsize)
			self.wfile = self.connection.makefile('wb', self.wbufsize)
			if self.headers.get('Proxy-Connection', '').lower() != 'close':
				self.close_connection = False
			else:
				self.close_connection = True

		def log_message(self, format, *args):
			log_file = open('sessions.log', 'a+', 1)
			log_file.write("%s - - [%s] %s\n" %(self.client_address[0],self.log_date_time_string(),format%args))
			print("%s - - [%s] %s\n" %(self.client_address[0],self.log_date_time_string(),format%args))

		do_PUT = do_GET
		do_POST = do_GET
		do_HEAD = do_GET
		do_DELETE = do_GET
		do_OPTIONS = do_GET

	class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
		pass

	server = ThreadingSimpleServer(('0.0.0.0', int(parsed_args.port)), partial(Proxy, parsed_args.block_website,parsed_args.block_content))
	server.serve_forever()

if not path.exists('certs'):
	makedirs('certs')
if not path.exists('cert.key'):
	gen_keys()


parser = ArgumentParser()
parser.add_argument("--port", default=8080)
parser.add_argument("--block-website", default=None)
parser.add_argument("--block-content", default=None)
run_server(parser.parse_args())
