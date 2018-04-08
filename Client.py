import socket
import DiffieHellman
import json


class ClientSocket:
	def __init__(self, debugflag):
		self.dh = DiffieHellman.DH()
		self.debugflag = debugflag

	def initDiffieHellman(self, socket):

		socket.send("connected".encode())

		# Step1: recive the shared primes and the public secret
		step1 = socket.recv(2048)

		if self.debugflag:
			print(step1)

		# Step 1.1: Parse them
		# print step1.decode()
		jsonData = json.loads(step1.decode())
		jsonData = jsonData["dh-keyexchange"]

		self.dh.base = int(jsonData["base"])
		self.dh.sharedPrime = int(jsonData["prime"])
		publicSecret = int(jsonData["publicSecret"])

		# Step2: calculate public secret and send to server
		calcedPubSecret = str(self.dh.calcPublicSecret())
		step2 = "{"
		step2 += "\"dh-keyexchange\":"
		step2 += "{"
		step2 += "\"step\": {},".format(2)
		step2 += "\"publicSecret\": {}".format(calcedPubSecret)
		step2 += "}}"
		socket.send(step2.encode())

		# Step3: calculate the shared secret
		self.dh.calcSharedSecret(publicSecret)

	def start_client(self, ip):
		# Start the Socket
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			sock.connect((ip, 20000));

			# Start the Key-Exchange
			self.initDiffieHellman(sock)
			print("The secret key is {}".format(self.dh.key))

		finally:
			# Close the Socket
			sock.close()
