#pragma once


#include "../sshay.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <queue>

struct hostent;
struct sockaddr_in;


class Socket {
public:
					Socket();
	virtual 		~Socket();

	bool 			Connect(string addr, int portnum);
	void 			Disconnect();
	bool 			IsConnected();

	bool 			Write(const ubyte *raw, uint32 len);
	bool 			HasData();
	ubyte* 			Read();	
	int 			LastSize();	
	int 			NextSize(bool blocking=false);
	int 			GetSocketID();

private:
	int 			socketID;
	int 			port;
	string 			strAddress;		// Store the address for debugging purposes
	hostent 		*server;
	sockaddr_in 	serverAddress;
	bool 			connected;

	int 			lastSize;
	ubyte 			*lptr;

	uint32 			recBytes;	// Received bytes
	uint32 			senBytes;	// Sent bytes

	queue< pair<uint32, ubyte*> >	
					pqueue;			// Queued packets

	void 			ProcessData(ubyte *data, uint32 len);
	uint32 			SplitPackets(ubyte *data, uint32 len);

	bool 			PopQueue();
};