#include "socket.h"
#include "../prot/packet.h"
#include "../prot/session.h"
#include "../mac/macsha1.h"
#include "../crypt/crypttdes.h"
#include "../globdata.h"

#include <fcntl.h>

/*
==================
Socket::Socket
==================
*/
Socket::Socket() {
	socketID 			= -1;
	server 				= NULL;
	connected 			= false;
	port 				= 22;
	lptr 				= NULL;
	recBytes 			= 0;
	senBytes 			= 0;

	while (!pqueue.empty()) 
		pqueue.pop();

	bzero((char*)&serverAddress, sizeof(serverAddress));
}

/*
==================
Socket::~Socket
==================
*/
Socket::~Socket() {
	Disconnect();

	if (lptr) {
		delete[] lptr;
	}

	while (!pqueue.empty()) {
		pair<uint32, ubyte*> p = pqueue.front();
		delete[] p.second;
		pqueue.pop();
	}
}

/*
==================
Socket::Connect
==================
*/
bool Socket::Connect(string addr, int portnum) {
	if (connected) {
		stringstream ss;
		ss << 	"Attempted to open connection on Socket "
				"already connected to " 
				<< strAddress << ":" << port
				<<". Opening new connection on "
				<< addr << ":" << portnum;
		Warning(ss.str().c_str());
		Disconnect();
	}

	port = portnum;
	strAddress = addr;

	server = gethostbyname(addr.c_str());
	if (!server) {
		Error("Failed to get host from name");
		return false;
	}


	socketID = socket(AF_INET, SOCK_STREAM, 0);
	if (socketID < 0) {
		Error("Failed to create socket", errno);
		return false;
	}

	serverAddress.sin_family = AF_INET;
	bcopy((char*)server->h_addr,
		  (char*)&serverAddress.sin_addr.s_addr,
		   server->h_length);
	serverAddress.sin_port = htons(port);

	int n = connect(socketID, (sockaddr*)&serverAddress, sizeof(serverAddress));
	if (n < 0) {
		Error("Failed to connect to host", errno);
		return false;
	}

	connected = true;

	return true;
}

/*
==================
Socket::Disconnect
==================
*/
void Socket::Disconnect() {
	if (connected == true && socketID != -1) {
		close(socketID);
	}

	connected 	= false;
	socketID 	= -1;
	server 		= NULL;
	port 		= 22;

	bzero((char*)&serverAddress, sizeof(serverAddress));
}

/*
==================
Socket::IsConnected
==================
*/
bool Socket::IsConnected() {
	return connected;
}

/*
==================
Socket::Write
==================
*/
bool Socket::Write(const ubyte *raw, uint32 len) {
	ubyte *data;

	if (!connected) {
		Warning("Tried to write to closed socket");
		return false;
	}

	if (!len || !raw) {
		Warning("Attempted to write NULL data to socket");
		return false;
	}

	data = new ubyte[len];
	memcpy(data, raw, len);

	if (Session::DoCipherPackets()) {
		uint32 ciphLen = len;
		if (Session::DoHashPackets()) {
			ciphLen -= 20;
		}

		if (ciphLen % 8) {
			Error("Socket::Write(): Cannot encrypt data! "
				  "The length of the data is not a factor of 8.",
				  	ciphLen);
			return false;
		}

		CryptTDES *ciph = Session::GetCipher();
		ubyte *enc = ciph->Encrypt(data, ciphLen);
		memcpy(data, enc, ciphLen);
	}

	// TODO: Verify MAC	

	int n = write(socketID, data, len);
	if (n < 0) {
		Warning("Failed to write to socket", errno);
		delete[] data;
		return false;
	}

	senBytes += n;

	Session::IncrementSequenceOut();

	delete[] data;
	return true;
}

/*
==================
Socket::HasData
==================
*/
bool Socket::HasData() {
	if (!connected || socketID == -1) {
		return false;
	}

	return (NextSize() > 0) || (!pqueue.empty());
}

/*
==================
Socket::Read

Returns a cached packet from 'queue' if available,
otherwise reads from the connection.
==================
*/
ubyte* Socket::Read() {
	if (lptr) {
		delete[] lptr;
		lptr = NULL;
	}

	if (PopQueue()) {
		return lptr;
	}

	if (!connected || socketID == -1) {
		Warning("Tried to read from closed socket");
		return NULL;
	}

	vector<ubyte> buffer;
	ubyte tmp[256];
	ubyte *data;
	int n = 0;

	do {
		n = recv(socketID, tmp, 256, 0);
		
		for (int i=0; i<n; i++) {
			buffer.push_back(tmp[i]);
		}
	} while (n == 256);

	if (n < 0) {
		Warning("Failed to read from socket", errno);
		lastSize = 0;
		return NULL;
	} else if (!buffer.size()) {
		Warning("The connection closed unexpectedly", errno);
		lastSize = 0;
		return NULL;
	} 

	data = new ubyte[buffer.size()];
	for (int i=0; i<buffer.size(); i++) {
		data[i] = buffer[i];
	}

	ProcessData(data, buffer.size());

	recBytes += buffer.size();

	Session::IncrementSequenceIn();

	PopQueue();

	return lptr;
}

/*
==================
Socket::LastSize
==================
*/
int Socket::LastSize() {
	return lastSize;
}

/*
==================
Socket::NextSize
==================
*/
int Socket::NextSize(bool blocking) {
	ubyte buf[8];
	int flag = fcntl(socketID, F_GETFL);

	if (!blocking) {
		/* Set the socket in non-blocking mode */
		fcntl(socketID, F_SETFL, flag | O_NONBLOCK);
	}

	int n = recv(socketID, buf, 8, MSG_PEEK);

	if (!blocking) {
		/* Revert to blocking */
		fcntl(socketID, F_SETFL, flag & ~(O_NONBLOCK));
	}

	if (n < 0) {
		if (errno != 11) {
			Error("Failed to peek for data", errno);
		}
	}

	return n;
}

/*
==================
Socket::GetSocketID
==================
*/
int Socket::GetSocketID() {
	return socketID;
}

/*
==================
Socket::ProcessData

If more than one packet is received at the same 
time, the packets must be divided and stored in
'pqueue'. 

If the server identification string has NOT arrived,
the packet is added directly to 'pqueue'.
==================
*/
void Socket::ProcessData(ubyte *data, uint32 len) {
	uint32 i = 0;

	if (GData::remoteid.length() == 0) {
		ubyte *buf = new ubyte[len];
		memcpy(buf, data, len);

		pair<uint32, ubyte*> p;
		p.first = len;
		p.second = buf;
		pqueue.push(p);
		return;
	}

	while (i < len) {
		uint32 ret = SplitPackets(data+i, len-i);
		if (!ret) {
			return;
		}
		i += ret;
	}
}

/*
==================
Socket::SplitPackets

Given an input of N+X bytes, where the first N bytes
make up an encrypted received packet, N is returned 
and the N first bytes are pushed at the back of 'pqueue'.
==================
*/
uint32 Socket::SplitPackets(ubyte *data, uint32 len) {
	ubyte *tmp, *buf;
	ubyte first[8];
	uint32 pacLen, remain, fullLen;
	CryptTDES *cipher = Session::GetCipher();

	if (len < 8) {
		Warning("Socket::SplitPackets(): "
				"len < 8", len);
		return 0;
	}

	if (Session::DoCipherPackets()) {
		/* Decrypt the first 8 bytes of the packet */
		tmp = cipher->Decrypt(data, 8);
		memcpy(first, tmp, 8);
	} else {
		memcpy(first, data, 8);
	}

	/* Retrieve the packet length */
	BytesToInt(pacLen, first);
	fullLen = pacLen + 4 + Session::DoHashPackets()*20;
	remain = pacLen - 4;

	if (fullLen > len) {
		Warning("Socket::SplitPackets(): "
				"FullLen > len", fullLen-len);
		return 0;
	}

	if (Session::DoCipherPackets()) {
		/* Decrypt the rest of the packet */
		tmp = cipher->Decrypt(data+8, remain);
	} else {
		tmp = new ubyte[remain];
		memcpy(tmp, data+8, remain);
	}

	/* Store the entire packet in buf */
	buf = new ubyte[fullLen];
	memcpy(buf+0, first, 8);
	memcpy(buf+8, tmp, remain);

	if (Session::DoHashPackets()) {
		memcpy(buf+8+remain, data+pacLen+4, 20);
	}
	if (!Session::DoCipherPackets()) {
		delete[] tmp;
	}

	/* Add the buffer to 'pqueue' */
	pair<uint32, ubyte*> p;
	p.first = fullLen;
	p.second = buf;

	pqueue.push(p);

	return fullLen;
}

/*
==================
Socket::PopQueue

If possible, sets 'lptr' and 'lastSize' to the
first element of 'pqueue'.
==================
*/
bool Socket::PopQueue() {
	if (lptr) {
		delete[] lptr;
		lptr = NULL;
	}

	if (!pqueue.empty()) {
		pair<uint32, ubyte*> p = pqueue.front();

		lastSize = p.first;
		lptr = p.second;

		pqueue.pop();
		return true;

	} else {
		lastSize = 0;
		lptr = NULL;
		return false;
	}
}