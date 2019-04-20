import socket, sys, struct, base64, time, requests
from thread import *

try:
	listening_port = int(raw_input("[*] Enter Listening Port Number: "))
except KeyboardInterrupt:
	print "\n[*] User Requested An Interrupt"
	print "[*] Application Exiting"
	sys.exit()

max_conn = 10 # Max Connection Queues to hold
buffer_size = 4096*4096# Max socket buffer size

f = open("blacklist.txt", "r")
blacklist_cidr = map(lambda x: x.strip(), f.readlines())
blocked_ips = []
for c in blacklist_cidr:
	ip, cidr = c.split("/")
	blocked_ips.append(ip)
	cidr = int(cidr)
	host_bits = 32 - cidr
	i = struct.unpack('>I', socket.inet_aton(ip))[0]
	start = (i >> host_bits) << host_bits
	end = start | ((1 << host_bits) - 1)
	for i in range(start, end):
		blocked_ips.append(socket.inet_ntoa(struct.pack('>I',i)))
if '127.0.0.1' in blocked_ips:
	if 'localhost' not in blocked_ips:
		blocked_ips.append('localhost')

# curl -x http://localhost:1025 --user neel:1234 http://www.baidu.com
users = ["neel:1234"]

reqs = {}
cached = []

def proxy_server(webserver, port, conn, data, addr, filename):
	try:
		print
		print cached
		print reqs
		print
		print webserver, port, filename
		for t in cached:
			if webserver == t[0]:
				r = requests.get(url='http://' + webserver + ':' + str(port), headers={"If-Modified-Since": t[2]})
				print r
				if r.status_code == 304:
					print 'cached response sent for ', webserver
					for rep in t[1]:
						conn.send(rep)
					conn.close()
					exit(0)
				else:
					break

		if (webserver in list(reqs.keys())) and abs(time.time() - reqs[webserver][1]) <= 60*5:
			reqs[webserver][0] += 1
		else:
			reqs[webserver] = [1, time.time()]

		add_to_cache = False
		if reqs[webserver][0] >= 3 and (webserver not in list(map(lambda x:x[0], cached))):
			add_to_cache = True

		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((webserver, port))
		if webserver in ['127.0.0.1', 'localhost']:
			s.send("GET " + filename + " HTTP/1.1\r\n\r\n")
		else:
			s.send(data)
		cached_reply = []
		while 1:
			reply = s.recv(buffer_size)
			if add_to_cache:
				cached_reply.append(reply)
			if len(reply) > 0:
				conn.send(reply)
			else:
				break

		if add_to_cache:
			if (len(cached) >= 3):
				del cached[0]
			print 'adding to cache'
			cached.append( ( webserver, cached_reply, time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()) ) )

		s.close()
		conn.close()

	except socket.error, (value, message):
		s.close()
		conn.close()
		sys.exit(1)

def conn_string(conn, data, addr, valid):
	try:
		first_line = data.split('\n')[0]
		url = first_line.split(' ')[1]
		http_pos = url.find("://")
		if (http_pos == -1):
			temp = url
		else:
			temp = url[(http_pos+3):]
		filename_pos = temp.find('/')
		if filename_pos == -1:
			filename = '/'
		else:
			filename = temp[filename_pos:]
		port_pos = temp.find(":") # Find the position of port (if any)
		webserver_pos = temp.find("/") # Find the end of the web server
		if webserver_pos == -1:
			webserver_pos = len(temp)
		webserver = ""
		port = -1
		if (port_pos == -1 or webserver_pos < port_pos):
			# Default port
			port = 80
			webserver = temp[:webserver_pos]
		else:
			# Specific port
			port = int((temp[(port_pos+1):])[:webserver_pos-port_pos-1])
			webserver = temp[:port_pos]

		if port not in list(range(20000, 20100)):
			conn.send("invalid port")
			conn.close()
			
		req_ip = socket.gethostbyname(webserver)
		if req_ip in blocked_ips:
			if valid:
				proxy_server(webserver, port, conn, data, addr, filename)
			else:
				conn.send("page forbidden")
				conn.close()
		else:
			proxy_server(webserver, port, conn, data, addr, filename)


	except Exception, e:
		pass

def start():
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Initiate scoket
		s.bind(('', listening_port)) # Bind socket for listening
		s.listen(max_conn) # Start listening for incoming connections
		print "[*] Initializing sockets...done"
		print "[*] Sockets binded successfully..."
		print ("[*] Server started successfully on port [ %d ]\n" % (listening_port))
	except Exception, e:
		print "[*] Unable to initialize socket"
		sys.exit(2)

	while 1:
		try:
			conn, addr = s.accept() # Accept connection from client
			data = conn.recv(buffer_size) # Receive client data
			data_fields = data.split('\n')
			valid = False
			for datum in data_fields:
				if (datum.find('Authorization: Basic') != -1):
					auth = base64.b64decode(datum[len('Authorization: Basic '):].strip())
					if auth in users:
						valid = True
					break
			start_new_thread(conn_string, (conn, data, addr, valid)) # Start a new thread
		except KeyboardInterrupt:
			s.close()
			print "[*] Proxy server shutting down..."
			sys.exit(1)
	s.close()

start()
