#include "channel.h"
#include "session.h"

/*
==================
Channel::Channel
==================
*/
Channel::Channel(CHDir dir, uint32 chn, string ty, Socket *s) {
	reqType 	= ty;
	socket  	= s;
	direction 	= dir;
	winSizeIn 	= 15000;
	winSizeOut 	= 0;
	maxSize 	= 0;

	if (dir == CH_CLI) {
		status = ST_CLOSED;
		recChan = chn;
		senChan = chn;
	} else {
		Error("Direction CH_SER is not implemented!");
	}
}

/*
==================
Channel::Init

If the client is the initiater, the intial request is sent and
the parameters are NULL and 0 respectively.

If the server is the initiater, the response is sent and the
data param contains the request packet sent from the server.
==================
*/
bool Channel::Init(ubyte *data, uint32 len) {
	if (direction == CH_CLI) {
		if (data || len) {
			return false;
		}

		if (!SendOpenRequest()) {
			return false;
		}

		return true;
	} 	

	Error("Direction CH_SER not implemented!");
	return false;
}

/*
==================
Channel::AdjustWindow
==================
*/
bool Channel::AdjustWindow(uint32 increment) {
	Message msg;

	msg.Add(SSH_MSG_CHANNEL_WINDOW_ADJUST);
	msg.AddUI(recChan);
	msg.AddUI(increment);

	if (!SendMessage(msg)) {
		return false;
	}

	winSizeIn += increment;
	return true;
}

/*
==================
Channel::SendInput
==================
*/
void Channel::SendInput(string input) {
	Message msg;

	if (!input.length()) {
		return;
	}

	msg.Add(SSH_MSG_CHANNEL_DATA);
	msg.AddUI(recChan);
	msg.AddUI(input.length());
	msg.Add(input);

	SendMessage(msg);
}

/*
==================
Channel::
==================
*/
void Channel::HandleMessage(const ubyte *data, uint32 len) {
	if (winSizeIn < 5000) {
		AdjustWindow(15000);
	}

	if (!len || !data) {
		Warning("Channel::HandleMessage(): NULL-data given!");
		return;
	}

	if (!IsPacketForMe(data, len)) {
		return;
	}

	winSizeIn -= len;

	Packet p(data, len);
	
	switch (p.type) {
		case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
			OnChanOpenConfirmation(data, len);
			break;
		case SSH_MSG_CHANNEL_SUCCESS:
			OnChanSuccess(data, len);
			break;
		case SSH_MSG_CHANNEL_FAILURE:
			OnChanFailure(data, len);
			break;
		case SSH_MSG_CHANNEL_WINDOW_ADJUST:
			OnWindowAdjust(data, len);
			break;
		case SSH_MSG_CHANNEL_DATA:
		case SSH_MSG_CHANNEL_EXTENDED_DATA:
			OnChanData(data, len);
			break;
		default:
			printf("[Chann] Unkown packet:  ");
			Session::GetSingleton()->DeterminePacket(data,len);
			break;
	}
}

/*
==================
Channel::IsPacketForMe
==================
*/
bool Channel::IsPacketForMe(const ubyte *data, uint32 len) {
	if (len > 10) {
		uint32 recp;
		BytesToInt(recp, data+6);

		return (recp == senChan);
	} 

	return false;
}

/*
==================
Channel::OnChanOpenConfirmation
==================
*/
void Channel::OnChanOpenConfirmation(const ubyte *data, uint32 len) {
	status = ST_CHAN_OPEN;
	printf("Channel openend\n");

	uint32 b = 6;

	BytesToInt(recChan, data+b);
	b += 4;

	BytesToInt(senChan, data+b);
	b += 4;

	BytesToInt(winSizeOut, data+b);
	b += 4;

	BytesToInt(maxSize, data+b);
	b += 4;

	printf("Rec chan: %i\nSen chan: %i\n", recChan, senChan);
	printf("Cur wind: %i\nMax pack: %i\n", winSizeOut, maxSize);

	SendTTYRequest();
}

/*
==================
Channel::OnChanSuccess
==================
*/
void Channel::OnChanSuccess(const ubyte *data, uint32 len) {
	printf("CHANNEL_SUCCESS received\n");

	if (status == ST_CHAN_OPEN) {
		status = ST_TTY_OPEN;
		printf("TTY open\n");

		SendShellRequest();
	} else if (status == ST_TTY_OPEN) {
		status = ST_SHELL_OPEN;
		printf("Shell open\n");
	}
}

/*
==================
Channel::OnChanFailure
==================
*/
void Channel::OnChanFailure(const ubyte *data, uint32 len) {
	HexDump(data, len, "ChanFailure");

	switch (status) {
		case ST_CLOSED:
			SendOpenRequest();
			break;

		case ST_CHAN_OPEN:
			SendTTYRequest();
			break;

		case ST_TTY_OPEN:
			SendShellRequest();
			break;
	}
}

/*
==================
Channel::OnWindowAdjust
==================
*/
void Channel::OnWindowAdjust(const ubyte *data, uint32 len) {
	uint32 increment;
	BytesToInt(increment, data+10);

	winSizeOut += increment;
	printf("Window adjust recvd: %i\n", increment);
}

/*
==================
Channel::OnChanData
==================
*/
void Channel::OnChanData(const ubyte *data, uint32 len) {
	uint32 plen, dlen;
	ubyte ub;
	Packet p(data, len);

	/* Raw payload length */
	plen = p.packetLength - p.paddingLength - 1;

	/* Actual data length */
	BytesToInt(dlen, data+10);
	//HexDump(data+14, dlen, "ascii");

	for (int i=0; i<dlen; i++) {
		ub = data[14+i];
		if (IsUbytePrintable(ub)) {
			printf("%c", ub);
		} else {
			HandleUnprintable(ub);
		}
	}
}

/*
==================
Channel::SendMessage

Send the desired message. If "initMsg==true", the 
window size and maximum packet size is NOT taken 
into any account.
==================
*/
bool Channel::SendMessage(Message &msg, bool initMsg) {
	uint32 len;

	len = msg.GetLength();

	if (!initMsg && (len > winSizeOut || len > maxSize)) {
		Warning("Message too long", len);
		printf("Current outgoing winsize: %i\n", winSizeOut);
		return false;
	}

	if (socket->Write(msg.GetData(), len)) {
		winSizeOut -= len * !initMsg;
	} else {
		return false;
	}

	return true;
}


/*
==================
Channel::SendOpenRequest
==================
*/
bool Channel::SendOpenRequest() {
	Message msg = GetOpenRequestMsg();
	return SendMessage(msg, true);
}

/*
==================
Channel::SendTTYRequest
==================
*/
bool Channel::SendTTYRequest() {
	Message msg = GetTTYRequestMsg();
	return SendMessage(msg, true);
}

/*
==================
Channel::SendShellRequest
==================
*/
bool Channel::SendShellRequest() {
	Message msg = GetShellRequestMsg();
	return SendMessage(msg, true);
}

/*
==================
Channel::GetOpenRequestMsg
==================
*/
Message Channel::GetOpenRequestMsg() {
	Message msg;

	msg.Add(SSH_MSG_CHANNEL_OPEN);
	msg.AddUI(reqType.length());
	msg.Add(reqType);
	msg.AddUI(senChan);
	msg.AddUI(winSizeIn); 	// Window IN
	msg.AddUI(35000);		// Max packet

	return msg;
}

/*
==================
Channel::GetTTYRequestMsg
==================
*/
Message Channel::GetTTYRequestMsg() {
	Message msg;
	uint32 chW, chH, pW, pH;

	GetTermDim(chW, chH, pW, pH);

	msg.Add(SSH_MSG_CHANNEL_REQUEST);
	msg.AddUI(recChan);
	msg.AddUI(7);
	msg.Add("pty-req");
	msg.Add(true);			// Want reply

	msg.AddUI(5);
	msg.Add("vt100");

	msg.AddUI(chW);
	msg.AddUI(chH);
	msg.AddUI(pW);
	msg.AddUI(pH);

	msg.AddUI(0);

	return msg;
}

/*
==================
Channel::GetShellRequestMsg
==================
*/
Message Channel::GetShellRequestMsg() {
	Message msg;

	msg.Add(SSH_MSG_CHANNEL_REQUEST);
	msg.AddUI(recChan);
	msg.AddUI(5);
	msg.Add("shell");
	msg.Add(true);

	return msg;
}

/*
==================
Channel::IsUbytePrintable
==================
*/
bool Channel::IsUbytePrintable(ubyte c) {
	if ( 	c == 9
		 || c == 10
		 || c == 27
		 ||(c >= 32
		 && c <= 126) ) {
		return true;
	}	

	return false;
}

/*
==================
Channel::HandleUnprintable
==================
*/
void Channel::HandleUnprintable(ubyte c) {
	switch (c) {
		case 8:
			printf("\b");
			break;

		case 27:	
			printf("\b \b");
			break;             

		case 13:
			printf("\b");
			break;

		default:
			printf("%c", c);
			break;
	}
}