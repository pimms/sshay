#include "session.h"
#include "../mac/macsha1.h"
#include "../crypt/crypttdes.h"
#include "../crypt/keyexchange.h"
#include "../globdata.h"
#include "connection.h"


Session* singleton = NULL;


/*
==================
static Session::GetSingleton
==================
*/
Session* Session::GetSingleton() {
	return singleton;
}

/*
==================
static Session::DoHashPackets
==================
*/
bool Session::DoHashPackets() {
	if (singleton) {
		return singleton->hashPackets;
	} 

	return false;
}

/*
==================
static Session::DoCipherPackets
==================
*/
bool Session::DoCipherPackets() {
	if (singleton) {
		return singleton->cipherPackets;
	}

	throw "Session::DoCipherPackets(): No singleton!";
	return false;
}

/*
==================
static Session::GetCipher
==================
*/
CryptTDES* Session::GetCipher() {
	if (singleton) {
		return singleton->cipher;
	}

	throw "Session::GetCipher(): No singleton!";
	return NULL;
}

/*
==================
static Session::GetSequenceOut
==================
*/
uint32 Session::GetSequenceOut() {
	if (singleton) {
		return singleton->sequenceOut;
	}

	throw "Session::GetSequenceNum(): No singleton!";
	return 0;
}

/*
==================
static Session::GetSequenceIn
==================
*/
uint32 Session::GetSequenceIn() {
	if (singleton) {
		return singleton->sequenceIn;
	}

	throw "Session::GetSequenceIn(): No singleton!";
	return 0;
}

/*
==================
static Session::IncrementSequenceOut

This method should be called from Socket::Write and
Socket::Read ONLY!
==================
*/
void Session::IncrementSequenceOut() {
	if (singleton) {
		singleton->sequenceOut++;
	} else {
		throw "Session::IncrementSequenceOut(): No singleton!";
	}
}

/*
==================
static Session::IncrementSequenceIn
==================
*/
void Session::IncrementSequenceIn() {
	if (singleton) {
		singleton->sequenceIn++;
	} else {
		throw "Session::IncrementSequenceIn(): No singleton!";
	}
}


// ======================================================


/*
==================
Session::Session
==================
*/
Session::Session() {
	singleton = this;
	hashPackets = false;
	cipherPackets = false;
	sequenceOut = 0;
	sequenceIn  = 0;

	kex 		= NULL;
	cipher 		= NULL; 		

	idSoftware = "SSHay_0.0";
	idProtnum  = "2.0";

	/* Only algorithms denoted as REQUIRED are supported */
	//nlKexAlgo.names.push_back("diffie-hellman-group14-sha1");
	nlKexAlgo.names.push_back("diffie-hellman-group1-sha1");
	
	nlServerHostKeyAlgo.names.push_back("ssh-dss");
	
	nlCiphers.names.push_back("3des-cbc");
	
	nlMac.names.push_back("hmac-sha1");

	nlComp.names.push_back("none");
	//nlLang.names.push_back("none");
}

/*
==================
Session::~Session
==================
*/
Session::~Session() {
	singleton = NULL;
	socket.Disconnect();

	if (kex) {
		delete kex;
	}

	if (cipher) {
		delete cipher;
	}
}

/*
==================
Session::Initiate

Connect to the host, send the protocol version 
and software identifier. True is returned on 
success, false on failure.

This method implements the setup and preparation
of the SSH-Transport Layer protocol.
==================
*/
bool Session::Initiate(string host, int port) {
	if (!socket.Connect(host, port)) {
		return false;
	}

	if (!ValidateServerID()) {
		Disconnect(SSH_DISCONNECT_PROTOCOL_ERROR);
		return false;
	}

	/* Identification packets are NOT counted! */
	sequenceIn = 0;
	sequenceOut = 0;

	/* Send the KEXINIT packet and store the sent payload
	 * in member variable "lKexinitpl".
	 * Store the server's KEXINIT packet in "rKexinitPl". */
	SendKexInit();

	if (!ReadKexInit()) {
		Disconnect(SSH_DISCONNECT_PROTOCOL_ERROR);
		return false;
	}

	/* Begin the Key Exchange */
	kex = new KeyExchange;
	kex->Init(DH_GROUP1, &socket);
	if (!kex->SendDHInit()) {
		return false;
	} 

	if (!kex->VerifyDHReply()) {
		Disconnect(SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
		return false;
	} 

	DeriveKeys();

	/* Send SSH_MSG_NEWKEYS */
	Message msg;
	msg.Add(SSH_MSG_NEWKEYS);
	socket.Write(msg.GetData(), msg.GetLength());
	//printf("Sent SSH_MSG_NEWKEYS\n");

	ubyte *data = socket.Read();
	uint32 len = socket.LastSize();

	if (IsPacketOfType(data, len, SSH_MSG_NEWKEYS)) {
		//printf("Received SSH_MSG_NEWKEYS\n");
	}
	
	hashPackets = true;
	cipherPackets = true;

	return true;
}

/*
==================
Session::UserAuthentication
==================
*/
bool Session::UserAuthentication() {
	//printf("Starting SSH-USERAUTH\n");
	if (!RequestAuth()) {
		return false;
	}

	if (!PasswordAuth()) {
		return false;
	}

	return true;
}

/*
==================
Session::RunConnection
==================
*/
int Session::RunConnection() {
	Connection connection(&socket);
	return connection.MainLoop();
}


// ======================================================


/*
==================
Session::Disconnect

Disconnect the current session. Callers of this method
are REQUIRED to drop whatever they're doing and let the
program terminate without causing trouble.
==================
*/
void Session::Disconnect(uint32 reason) {
	printf("Client terminating session. Reason: %s\n", 
			GetDCReasonString(reason).c_str());

	Message msg;

	msg.Add(SSH_MSG_DISCONNECT);
	msg.AddUI(reason);

	/* Reason string and language tag are currently unsupported */
	for (int i=0; i<8; i++) {
		msg.Add(0);
	}

	if (!socket.Write(msg.GetData(), msg.GetLength())) {
		printf("Failed to disconnect - "
			   "The server disconnected first :(\n");
	}
	socket.Disconnect();
}

/*
==================
Session::ValidateServerID
==================
*/
bool Session::ValidateServerID() {
	string id = GetIDMessage();
	GData::localid = id;

	//printf("Sending: %s\n", id.c_str());
	socket.Write((const ubyte*)id.c_str(), id.length()); 

	ubyte *data = socket.Read();
	if (data) {
		//printf("reply: %s\n", data);

		/* Copy the identification string, remove CRLF */
		char *c = (char*)data;
		while (*c != 13 && *c) {
			GData::remoteid += *c;
			c++;
		}

		/* Discard the initial "SSH" */
		char *strdiv = strtok((char*)data, "-");

		/* Get the version number */
		strdiv = strtok(NULL, "-");
		if (!strdiv) {
			Error("Bad reply from server");
			return false;
		}
		//printf("Server SSH Version:  %s ", strdiv);

		if (atof(strdiv) < 1.98 || atof(strdiv) > 2.02) {
			//printf("%s[INCOMPATIBLE]%s\n", CRED, CWHITE);
			return false;
		} else {
			//printf("[compatible]\n");
			return true;
		}
	}

	return false;
}

/*
==================
Session::SoundKexInit

Send the key-exchange init packet
==================
*/
void Session::SendKexInit() {
	Message msg = GetKexInitMessage();
	socket.Write(msg.GetData(), msg.GetLength());

	//printf("Sent KEXINIT\n");

	/* Store the sent payload in lKexinitPl */
	Packet p(msg.GetData(), msg.GetLength());

	GData::localKexinitlen = p.packetLength - p.paddingLength - 1;
	GData::localKexinit = new ubyte[GData::localKexinitlen];

	memcpy(	GData::localKexinit, 
			msg.GetData()+5, 
			GData::localKexinitlen );
}

/*
==================
Session::ReadKexInit
==================
*/
bool Session::ReadKexInit() {
	ubyte *data = socket.Read();

	if (!IsPacketOfType(data, socket.LastSize(), 
						SSH_MSG_KEXINIT)) {
		return false;
	}

	//printf("Received MSG_KEXINIT\n");	

	/* Store the payload in rKexinitPl */
	KexPacket kex(data, socket.LastSize());

	GData::remoteKexinitlen = kex.packetLength-kex.paddingLength-1;
	GData::remoteKexinit = new ubyte[GData::remoteKexinitlen];
	memcpy(	GData::remoteKexinit, 
			data+5, 
			GData::remoteKexinitlen );

	return true;
}

/*
==================
Session::RequestAuth
==================
*/
bool Session::RequestAuth() {
	string service  = "ssh-userauth";
	Message msg;
	ubyte *data;

	msg.Add(SSH_MSG_SERVICE_REQUEST);
	msg.AddUI(service.length());
	msg.Add(service);
	
	socket.Write(msg.GetData(), msg.GetLength());

	data = socket.Read();
	//DeterminePacket(data, socket.LastSize());

	if (!IsPacketOfType(data, socket.LastSize(),
		SSH_MSG_SERVICE_ACCEPT)) {
		return false;
	} 

	return true;
}

/*
==================
Session::PasswordAuth

Attempt to verify the user via password authentcation.
==================
*/
bool Session::PasswordAuth() {
	string service  = "ssh-connection";
	string method   = "password";
	string user, password;
	Message msg;
	ubyte *data;
	uint32 len;

	do {
		printf("Username: ");
		getline(cin, user);

		SetStdinEcho(false);
		printf("Password: ");
		getline(cin, password);
		printf("\n");
		SetStdinEcho(true);

		msg.Add(SSH_MSG_USERAUTH_REQUEST);
		msg.AddUI(user.length());
		msg.Add(user);
		msg.AddUI(service.length());
		msg.Add(service);
		msg.AddUI(method.length());
		msg.Add(method);
		msg.Add(0);
		msg.AddUI(password.length());
		msg.Add(password);	

		socket.Write(msg.GetData(), msg.GetLength());

		data = socket.Read();
		len = socket.LastSize();

		if (!len) {
			return false;
		}

		if (IsPacketOfType(data, len, SSH_MSG_USERAUTH_SUCCESS)) {
			printf("Login successful!\n\n");
			break;
		} else if (IsPacketOfType(data, len, SSH_MSG_USERAUTH_FAILURE)) {
			printf("User authentication failed.\n\n");
		}
	} while (true);

	return true;
}

/*
==================
Session::DeriveKeys
==================
*/
void Session::DeriveKeys() {
	if (cipher) {
		delete cipher;
	}
	cipher = new CryptTDES;

	CreateKey(cipher->ivEnc, 'A', 8);
	CreateKey(cipher->ivDec, 'B', 8);

	CreateKey(cipher->keyEnc, 'C', 24);
	CreateKey(cipher->keyDec, 'D', 24);

	CreateKey(GData::macKeyOut, 'E', 20);
	CreateKey(GData::macKeyIn,  'F', 20);
}

/*
==================
Session::CreateKey

This method generates keys and IV`s as defined
in RFC-4253, section 7.2.
==================
*/
void Session::CreateKey(ubyte *buf, char ch, uint32 reqlen) {
	MacSHA1 mac;
	uint32 pos = 0;
	uint32 len = 0;
	uint32 steps = 0;
	ubyte *pkey[32] = { NULL };	// Maximum: 32 * maclen
	uint32 sharelen = 0;
	ubyte *shared = NULL;
	uint32 origLen = reqlen;

	sharelen = GData::sharedSecret->GetRawLength();
	shared = new ubyte[sharelen];
	GData::sharedSecret->GetRawBytes(shared);

	mac.Add(shared, sharelen);
	mac.Add(GData::exchangeHash, 20);
	mac.Add(ch);
	mac.Add(GData::exchangeHash, 20);

	len = MIN(reqlen, 20);
	memcpy(buf, mac.GetHash(), len);
	pos    += len;
	reqlen -= len;

	while (reqlen > 0) {
		pkey[steps] = new ubyte[20];
		memcpy(pkey[steps], mac.GetHash(), 20);

		mac.Clear();
		mac.Add(shared, sharelen);
		mac.Add(GData::exchangeHash, 20);
		
		for (int i=0; i<steps+1; i++) {
			mac.Add(pkey[i], 20);
		}

		len = MIN(reqlen, 20);
		memcpy(buf+pos, mac.GetHash(), len);
		pos    += len;
		reqlen -= len;

		steps++;
	}

	delete[] shared;

	for (int i=0; i<steps; i++) {
		delete[] pkey[i];
	}
}


// ======================================================

/*
==================
Session::GetIDMessage
==================
*/
string Session::GetIDMessage() {
	string idstring;

	idstring = "SSH-" + idProtnum + "-" + idSoftware;

	if (idComments.length()) {
		/* Replace spaces with underscores */
		for (unsigned i=0; i<idComments.length(); i++) {
			if (idComments[i] == ' ') {
				idComments[i] = '_';
			}
		}
		idstring += " " + idComments;
	}

	/* Add <CR LF> */
	idstring += (char)13;
	idstring += (char)10;

	return idstring;
}

/*
==================
Session::GetKexInitMessage
==================
*/
Message Session::GetKexInitMessage() {
	Message msg;

	msg.Add(SSH_MSG_KEXINIT);

	for (unsigned i=0; i<16; i++) {
		msg.Add((char)rand()%255);
	}

	msg.Add(nlKexAlgo.GetString());
	msg.Add(nlServerHostKeyAlgo.GetString());
	msg.Add(nlCiphers.GetString());
	msg.Add(nlCiphers.GetString());
	msg.Add(nlMac.GetString());
	msg.Add(nlMac.GetString());
	msg.Add(nlComp.GetString());
	msg.Add(nlComp.GetString());
	msg.Add(nlLang.GetString());
	msg.Add(nlLang.GetString());

	ubyte resAndNextKex[5] = {0};
	msg.Add(resAndNextKex, 5);

	return msg;
}


// ======================================================


/*
==================
Session::DeterminePacket
==================
*/
void Session::DeterminePacket(const ubyte *packet, uint32 len) {
	if (len >= 6) {
		ubyte flag = packet[5];

		switch (flag) {
			case SSH_MSG_DISCONNECT:
				printf("Server disconnected. ");
				DbgPrintDCReason(packet, len);
				break;

			case SSH_MSG_UNIMPLEMENTED:
				printf("Received MSG_UNIMPLEMENTED\n");
				break;

			case SSH_MSG_DEBUG:
				printf("Received DEBUG-packet\n");
				break;

			case SSH_MSG_SERVICE_REQUEST:
				printf("Received MSG_SERVICE_REQUEST\n");
				break;

			case SSH_MSG_SERVICE_ACCEPT:
				printf("Received MSG_SERVICE_ACCEPT\n");
				break;

			case SSH_MSG_KEXINIT:
				printf("Received KEXINIT\n"); 
				break;

			case SSH_MSG_NEWKEYS:
				printf("Received NEWKEYS\n");
				break;

			case SSH_MSG_USERAUTH_REQUEST:
				printf("Received USERAUTH_REQUEST\n");
				break;

			case SSH_MSG_USERAUTH_FAILURE:
				printf("Received USERAUTH_FAILURE\n");
				break;

			case SSH_MSG_USERAUTH_SUCCESS:
				printf("Received USERAUTH_SUCCESS\n");
				break;

			case SSH_MSG_USERAUTH_BANNER:
				printf("Received USERAUTH_BANNER\n");
				break;

			case SSH_MSG_GLOBAL_REQUEST:
				printf("Received GLOBAL_REQUEST\n");
				break;

			case SSH_MSG_REQUEST_SUCCESS:
				printf("Received REQUEST_SUCCESS\n");
				break;

			case SSH_MSG_REQUEST_FAILURE:
				printf("Received REQUEST_FAILURE\n");
				break;

			case SSH_MSG_CHANNEL_OPEN:
				printf("Received CHANNEL_OPEN\n");
				break;

			case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
				printf("Received CHANNEL_OPEN_CONFIRM\n");
				break;

			case SSH_MSG_CHANNEL_OPEN_FAILURE:
				printf("Received CHANNEL_OPEN_FAILURE\n");
				break;

			case SSH_MSG_CHANNEL_WINDOW_ADJUST:
				printf("Received WINDOW_ADJUST\n");
				break;

			case SSH_MSG_CHANNEL_DATA:
				printf("Received CHANNEL_DATA\n");
				break;

			case SSH_MSG_CHANNEL_EXTENDED_DATA:
				printf("Received CHANNEL_EXTENDED_DATA\n");
				break;

			case SSH_MSG_CHANNEL_EOF:
				printf("Received CHANNEL_EOF\n");
				break;

			case SSH_MSG_CHANNEL_CLOSE:
				printf("Received CHANNEL_CLOSE\n");
				break;

			case SSH_MSG_CHANNEL_REQUEST:
				printf("Received CHANNEL_REQUEST\n");
				break;

			case SSH_MSG_CHANNEL_SUCCESS:
				printf("Received CHANNEL_SUCCESS\n");
				break;

			case SSH_MSG_CHANNEL_FAILURE:
				printf("Received CHANNEL_FAILURE\n");
				break;

			default:
				printf("Received unidentified packet (%i)\n", flag);
				break;
		}
	}
}

/*
==================
Session::IsPacketOfType

Check the type of the received data without
instantiating a Packet-object.
==================
*/
bool Session::IsPacketOfType(const ubyte *packet, uint32 len, 
											int type) {
	if (len >= 6) {
		return (packet[5] == type);
	}

	return false;
}

/*
==================
Session::GetDisconnectReason
==================
*/
string Session::GetDCReasonString(uint32 reason) {
	switch (reason) {
		case SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT:
			return "HOST_NOT_ALLOWED_TO_CONNECT";
			break;

		case SSH_DISCONNECT_PROTOCOL_ERROR:
			return "PROTOCOL_ERROR";
			break;

		case SSH_DISCONNECT_KEY_EXCHANGE_FAILED:
			return "KEY_EXCHANGE_FAILED";
			break;

		case SSH_DISCONNECT_RESERVED:
			return "RESERVED (should never occur)";
			break;

		case SSH_DISCONNECT_MAC_ERROR:
			return "MAC_ERROR";;
			break;

		case SSH_DISCONNECT_COMPRESSION_ERROR:
			return "COMPRESSION_ERROR";
			break;

		case SSH_DISCONNECT_SERVICE_NOT_AVAILABLE:
			return "SERVICE_NOT_AVAILABLE";
			break;

		case SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED:
			return "PROTOCOL_VERSION_NOT_SUPPORTED";
			break;

		case SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE:
			return "HOST_KEY_NOT_VERIFIABLE";
			break;

		case SSH_DISCONNECT_CONNECTION_LOST:
			return "CONNECTION_LOST";
			break;

		case SSH_DISCONNECT_BY_APPLICATION:
			return "DISCONNECT_BY_APPLICATION";
			break;

		case SSH_DISCONNECT_TOO_MANY_CONNECTIONS:
			return "TOO_MANY_CONNECTIONS";
			break;

		case SSH_DISCONNECT_AUTH_CANCELLED_BY_USER:
			return "AUTH_CANCELLED_BY_USER";
			break;

		case SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE:
			return "NO_MORE_AUTH_METHODS_AVAILABLE";
			break;

		case SSH_DISCONNECT_ILLEGAL_USER_NAME:
			return "ILLEGAL_USER_NAME";
			break;

		default:
			return "UNDEFINED";
			break;
	}
}

/*
==================
Session::DbgPrintDCReason

Print the reson for a disconnected connection.
==================
*/
void Session::DbgPrintDCReason(const ubyte *packet, uint32 len) {
	uint32 b = 5;

	if (len >= 10) {
		if (packet[b++] != SSH_MSG_DISCONNECT) {
			return;
		}

		uint32 reason;
		BytesToInt(reason, packet+6);
		b += sizeof(uint32);

		printf("Reason: %s\n", GetDCReasonString(reason).c_str());

		/* Get the description string */
		uint32 len;
		BytesToInt(len, packet+b);
		b += sizeof(uint32);

		if (len) {
			char *str = new char[len+1];
			memcpy(str, packet+b, len);
			str[len] = 0;
			printf("Server reason: %s\n", str);
			delete[] str;
		}
	}
}