# coding=utf-8
import SocketServer
import DiffieHellman
import json


class ServerSocket(SocketServer.BaseRequestHandler):
	"""
	Diffie Hellman schlüsselaustausch durchführen
	"""
	def initDiffieHellman(self):
		if self.request.recv(1024).decode() != "connected":
			print("Error while connecting")

		publicSecret = self.dh.calcPublicSecret()
		# print publicSecret

		# Step1: share primes and public secret
		step1 = "{"
		step1 += "\"dh-keyexchange\":"
		step1 += "{"
		step1 += "\"step\": {},".format(1)
		step1 += "\"base\": {},".format(self.dh.base)
		step1 += "\"prime\": {},".format(self.dh.sharedPrime)
		step1 += "\"publicSecret\": {}".format(publicSecret)
		step1 += "}}"
		#print step1.encode()
		self.request.send(step1.encode())

		# step2: recive the public secret from client
		step2 = self.request.recv(2048)

		if self.debugflag:
			print(step2)

		# step 2.1 Parse them
		jsonData = json.loads(step2.decode())
		jsonData = jsonData["dh-keyexchange"]

		publicSecret = int(jsonData["publicSecret"])

		# step3: calculate the shared secret
		self.dh.calcSharedSecret(publicSecret)

	# Client connected
	def handle(self):
		self.debugflag = self.server.conn
		self.dh = DiffieHellman.DH()

		# print the Client-IP
		print("[{}] Client connected.".format(self.client_address[0]))

		# init
		self.initDiffieHellman()
		print("> The secret key is {}\n".format(self.dh.key))

def start_server(debugflag):
	# start the server and serve forever

	SocketServer.ThreadingTCPServer.allow_reuse_address = True
	server = SocketServer.ThreadingTCPServer(("", 20000), ServerSocket)

	# pass the debug-flag to the SocketServer-Class
	server.conn = debugflag

	# And serve
	server.serve_forever()
