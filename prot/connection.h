#pragma once

#include "channel.h"
#include "../sshay.h"
#include "../net/socket.h"

/*
==================
Connection

Implements the SSH-CONNECTION Protocol.
Before an obejct of this class is instantiated,
the user MUST be authorized access by the server.
==================
*/
class Connection {
public:
					Connection(Socket *s);
					~Connection();
	int 			MainLoop();

private:
	Socket 			*socket;
	bool 			quit;

	Channel 		*channel;

	void 			DispatchPacket();

	void 			HandleInput();
};