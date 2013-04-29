#include "globdata.h"
#include "prot/packet.h"

/*
==================
Static Members
==================
*/
string 		 GData::remoteid;
string 		 GData::localid;
ubyte* 		 GData::localKexinit 		= NULL;;
ubyte* 		 GData::remoteKexinit 		= NULL;;
uint32 		 GData::localKexinitlen 	= 0;
uint32 		 GData::remoteKexinitlen 	= 0;
KexDHPacket* GData::dhReply 			= NULL;
DSSBlob* 	 GData::dssBlob 			= NULL;
ubyte 		 GData::exchangeHash[20] 	= { 0 };
MPInt* 		 GData::sharedSecret 		= NULL;
ubyte 		 GData::macKeyOut[20] 		= { 0 };
ubyte 		 GData::macKeyIn[20]	 	= { 0 };

/*
==================
GData::Clear
==================
*/
void GData::Clear() {
	if (localKexinit) {
		delete[] localKexinit;
		localKexinit = NULL;
	}

	if (remoteKexinit) {
		delete[] remoteKexinit;
		remoteKexinit = NULL;
	}

	if (dhReply) {
		delete dhReply;
		dhReply = NULL;
	}

	if (dssBlob) {
		delete dssBlob;
		dssBlob = NULL;
	}

	if (sharedSecret) {
		delete sharedSecret;
		sharedSecret = NULL;
	}
}
