#pragma once

#include "sshay.h"

struct KexDHPacket;
struct DSSBlob;
struct MPInt;

/*
==================
GData

Important data and unique packets which are used
at later points are stored in this Singleton.

All data is public and stored in static variables.
==================
*/
class GData {
public:
	static void 		Clear();

	/* Identification strings */
	static string 		remoteid;
	static string 		localid;

	/* KEXINIT payloads */
	static ubyte		*localKexinit;
	static ubyte 		*remoteKexinit;
	static uint32 		localKexinitlen;
	static uint32 		remoteKexinitlen;

	/* KexDH server reply */
	static KexDHPacket 	*dhReply;
	static DSSBlob		*dssBlob;
	static ubyte 		exchangeHash[20];

	/* The shared secret K */
	static MPInt 		*sharedSecret;

	/* Integrity keys */
	static ubyte 		macKeyOut[20];
	static ubyte 		macKeyIn[20];
};