#pragma once

#include "../sshay.h"
#include "../net/socket.h"
#include "packet.h"
#include "channel.h"

class KeyExchange;
class CryptTDES;

/*
==================
Session

The main class handling the SSH-session
==================
*/
class Session {
public:
	static Session* GetSingleton();
	static bool DoHashPackets();
	static bool DoCipherPackets();
	static CryptTDES *GetCipher();
	static uint32 GetSequenceOut();
	static uint32 GetSequenceIn();
	static void	IncrementSequenceOut();
	static void IncrementSequenceIn();


				Session();
				~Session();
	bool 		Initiate(string host, int port);
	bool 		UserAuthentication();
	int 		RunConnection();

private:
	Socket 		socket;
	KeyExchange *kex;
	CryptTDES 	*cipher;
	uint32 		sequenceOut;
	uint32 		sequenceIn;

	/* Local version identifiers */
	string 		idSoftware;
	string 		idProtnum;
	string		idComments;

	/* Supported algorithms */
	NameList 	nlKexAlgo;				// Key ex
	NameList 	nlServerHostKeyAlgo;	// Host keys
	NameList 	nlCiphers;				// Ciphers
	NameList 	nlMac;					// MAC algorithms
	NameList 	nlComp;					// UNSUPPORTED
	NameList 	nlLang;					// UNSUPPORTED

	/* Do we attach hash to the packets? */
	bool 		hashPackets;

	/* Do we encrypt packets yet? */
	bool 		cipherPackets;

	/* Close the current session */
	void 		Disconnect(uint32 reason);

	/* Protocol-step methods */
	bool		ValidateServerID();
	void 		SendKexInit();
	bool 		ReadKexInit(); 		// Validate the server's reply

	/* User Authentication Methods */
	bool 		RequestAuth();
	bool 		PasswordAuth();

	/* Key Derivation methods */
	void 		DeriveKeys();
	void 		CreateKey(ubyte *buf, char ch, uint32 reqlen);

	/* Message methods */
	string  	GetIDMessage();
	Message 	GetKexInitMessage();


public:
	/* Packet identification */
	void 		DeterminePacket(const ubyte *packet, uint32 len);
	bool 		IsPacketOfType(const ubyte *packet, uint32 len, 
												int type);
	string 		GetDCReasonString(uint32 reason);

	/* Debug output */
	void 		DbgPrintDCReason(const ubyte *packet, uint32 len);
};