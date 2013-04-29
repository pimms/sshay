#pragma once

#include "../sshay.h"

class Socket;
struct NameList;
struct MPInt;
struct DSSBlob;

/*
==================
Message

Raw data ready to be written to a socket.
To use, simply add data to the payload-vector manually
or via the Add-methods.
==================
*/
struct Message {
			Message();
			~Message();
	ubyte* 	GetData();
	uint32	GetLength();
	ubyte 	GetPaddingLength();
	void 	Add(ubyte ub);
	void 	AddUI(uint32 ui);
	void 	Add(string s);
	void 	Add(const ubyte *c, int len);
	void 	Add(MPInt &mpint);

	vector<ubyte> payload;

private:
	/* The last returned array */
	ubyte*	lptr;
};




// ============================================= //
// ==               SSH TYPES                 == //
// ============================================= //  

/*
==================
NameList

Used primarily in the KEXINIT-phase
==================
*/
struct NameList {
					NameList();
					NameList(const ubyte *, uint32, int &myLen);
	void 			SetFromRaw(const ubyte *, uint32, int &myLen);

	string 			GetString();
	void 			Display();

	vector<string> 	names;
};

/*
==================
MPInt

High precision integer. Works as a wrapper around
an "mpz_t" from the GNU MP library.

If "leadingZero == true", GetRawBytes will append
a leading zero to pad a short mpint.
==================
*/
struct MPInt {
					MPInt();
					~MPInt();

	/* The total byte-length of the "mpint" is returned. */
	uint32 			SetFromRaw(const ubyte*, uint32);

	uint32 			GetRawLength();
	void 			GetRawBytes(ubyte *buffer);

	uint32 			len;
	mpz_class 		mpz;
	bool 			leadingZero;

private:
};

/*
==================
DSSBlob
==================
*/
struct DSSBlob {
				DSSBlob();
				~DSSBlob();
				
	/* The total length of the DSS-field is returned */
	uint32 		SetFromRaw(const ubyte *packet, uint32 paclen);

	MPInt 		p;
	MPInt 		q;
	MPInt 		g;
	MPInt 		y;

	/* Keep the raw data */
	uint32 		rawLen;
	ubyte 		*raw;

	uint32  	lenp;
	uint32 		lenq;
	uint32 		leng;
	uint32 		leny;
};




// ============================================= //
// ==                 PACKETS                 == //
// ============================================= //  

/*
==================
Packet

The Packet struct is only used for INCOMING packets.
Derivatives of Packet are the ones doing all the work.

The standard fields (excluding the payload) are read
by the Packet struct. 
==================
*/
struct Packet {
	uint32 		packetLength;
	ubyte 		paddingLength;
	ubyte 		type;
	ubyte 		mac[20];	

				Packet(const ubyte *raw, uint32 len);
	bool 		IsOfType(ubyte ty);
};

/*
==================
KexPacket

This packet-format is used during the initial
negotiation phase. The format is as specified
by http://tools.ietf.org/html/rfc4253, section 7.1:
	byte         SSH_MSG_KEXINIT
	byte[16]     cookie (random bytes)
	name-list    kex_algorithms
	name-list    server_host_key_algorithms
	name-list    encryption_algorithms_client_to_server
	name-list    encryption_algorithms_server_to_client
	name-list    mac_algorithms_client_to_server
	name-list    mac_algorithms_server_to_client
	name-list    compression_algorithms_client_to_server
	name-list    compression_algorithms_server_to_client
	name-list    languages_client_to_server
	name-list    languages_server_to_client
	boolean      first_kex_packet_follows
	uint32       0 (reserved for future extension)
==================
*/
struct KexPacket : public Packet {
				KexPacket(const ubyte *raw, int len);

	// ==== Payload ====
	byte 		cookie[16];

	NameList 	kexAlgo;
	NameList 	serverHostKeyAlgo;
	
	NameList 	encrypt_clientServer;
	NameList 	encrypt_serverClient;
	
	NameList 	mac_clientServer;
	NameList 	mac_serverClient;
	
	NameList 	comp_clientServer;
	NameList 	comp_serverClient;

	NameList 	lang_clientServer;
	NameList 	lang_serverClient;

	bool 		firstKexFollows;
	uint32 		reserved;
};

/*
==================
KexDHPacket

This packet holds the data received in the
SSH_MSG_KEXDH_REPLY packet sent from the server.

The format is specified in SSH-TRANS:
	byte      	SSH_MSG_KEXDH_REPLY
  	string   	server public host key and certificates (K_S).
				This client only supports shh-dss, so this field
				contains the mpints: p, q, g and y.
	mpint     	f
  	string    	signature of H. This field contains for DSS-
  				signatures the R and S components of the signature.
  				They are both 160 bit.
==================
*/
struct KexDHPacket : public Packet {
				KexDHPacket(const ubyte *raw, uint32 len);
				~KexDHPacket();

	DSSBlob 	dss;
	MPInt 		dhF;
	ubyte 		dssR[20];
	ubyte 		dssS[20];

	/* Keep the raw F data */
	uint32 		rawFlen;
	ubyte 		*rawF;
};