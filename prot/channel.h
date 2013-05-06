#pragma once

#include "../sshay.h"
#include "../net/socket.h"
#include "packet.h"

/*
==================
CHDir

Used to indicate which host initiated the channel during creation.
==================
*/
enum CHDir {
	CH_CLI,		// The client initiated the channel
	CH_SER,		// The server initiated the channel
};

/*
==================
CHStat

Inicates the status of the channel. The states of the channel
start at ST_CLOSED and moves it way up to ST_TTY_ACTIVE.
==================
*/
enum CHStat {
	ST_CLOSED,		// The channel is closed (initial state).
	ST_CHAN_OPEN, 	// The channel is open
	ST_TTY_OPEN, 	// The tty is open and active as all hell.
	ST_SHELL_OPEN,	// The shell is active
};

/*
==================
Channel

Encapsulates a channel as specified in [SSH-CONN], RFC-4254.
==================
*/
class Channel {
public:
				Channel(CHDir,uint32 chnl, string type, Socket *s);
	bool	 	Init(ubyte *data=NULL, uint32 len=0);
	bool 		AdjustWindow(uint32 increment);

	void 		SendInput(string input);
	void 		HandleMessage(const ubyte *data, uint32 len);

	uint32 		GetRecipientChn() { return recChan; }
	uint32 		GetSenderChn()    { return senChan; }

protected:
	CHStat		status;
	CHDir 		direction;	
	Socket 		*socket;

	string 		reqType;	// Channel type
	uint32 		recChan;	// Recipient Channel
	uint32 		senChan;	// Sender Channel
	uint32 		winSizeIn;	// Window size in
	uint32 		winSizeOut;	// Window size out
	uint32 		maxSize;	// Maximum packet size

	/* Message Handlers */
	bool 		IsPacketForMe(const ubyte*, uint32);
	void 		OnChanOpenConfirmation(const ubyte*, uint32);
	void 		OnChanSuccess(const ubyte*, uint32);
	void 		OnChanFailure(const ubyte*, uint32);
	void 		OnWindowAdjust(const ubyte*,uint32);
	void 		OnChanData(const ubyte*, uint32);

	bool 		SendMessage(Message &msg, bool initMsg=false);
	bool 		SendOpenRequest();
	bool 		SendTTYRequest();
	bool 		SendShellRequest();

	Message 	GetOpenRequestMsg();
	Message 	GetTTYRequestMsg();
	Message 	GetShellRequestMsg();

	bool 		IsUbytePrintable(ubyte c);
	void 		HandleUnprintable(ubyte c);

	void 		EraseChar();
};