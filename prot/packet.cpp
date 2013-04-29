#include "packet.h"
#include "../prot/session.h"
#include "../globdata.h"
#include "../mac/macsha1.h"

#include <openssl/hmac.h>

/*
==================
Message::Message
==================
*/
Message::Message() {
	lptr = NULL;
}

/*
==================
Message::~Message
==================
*/
Message::~Message() {
	if (lptr) {
		delete[] lptr;
	}
}

/*
==================
Message::GetData

If Message::addLengths is TRUE, the first
four bytes of the packet is a uint32 holding the
length of the packet.

len = total - sizeof(len) - sizeof(MAC)

5 is used as the default added length to
include the byte used as the padding-length field.
==================
*/
ubyte* Message::GetData() {
	if (lptr) {
		delete[] lptr;
		lptr = NULL;
	}

	uint32 len = GetLength();
	ubyte *data = new ubyte[len];
	
	/* Add the payload */
	for (unsigned i=0; i<payload.size(); i++) {
		data[i+5] = payload[i];
	}

	/* Add the padding */
	ubyte padlen = GetPaddingLength();
	uint32 padstart = 5 + payload.size();

	for (int i=0; i<padlen; i++) {
		data[padstart+i] = ubyte(rand()%255);
	}


	/* The LENGTH field does NOT include the
	 * LENGTH field itself, nor does it contain
	 * the length of the MAC.
	 */
	uint32 lengthField = len - 4 - 20*Session::DoHashPackets();

	ubyte *blen = (ubyte*)&lengthField;
	data[3] = blen[0];
	data[2] = blen[1];
	data[1] = blen[2];
	data[0] = blen[3];

	// Add the padding length
	data[4] = padlen;

	/* Add the mac */
	if (Session::DoHashPackets()) {
		/* TODO: Clean up this god awful mess */
		MacSHA1 mac;
		mac.AddUI(Session::GetSequenceOut());
		mac.Add(data, len - 20);

		const EVP_MD *evp = EVP_sha1();
		HMAC_CTX ctx;
		HMAC_Init(&ctx, GData::macKeyOut, 20, evp);
		HMAC_Update(&ctx, mac.GetBuffer(), mac.GetBufferLength());
		HMAC_Final(&ctx, data+len-20, NULL);
	}

	lptr = data;
	return data;
}

/*
==================
Message::GetLength

The FINAL length is returned. 
==================
*/
uint32 Message::GetLength() {
	uint32 len = 5;
	len += payload.size();	// obviously
	len += GetPaddingLength();

	if (len % 8) {
		Error("Message::GetLength(): len is not a factor of 8!");
	}

	if (Session::DoHashPackets()) {
		len += 20;
	}

	return len;
}

/*
==================
Message::GetPaddingLength
==================
*/
ubyte Message::GetPaddingLength() {
	uint32 len = payload.size() + 5;
	ubyte padlen = 4;

	while ((padlen + len) % 8 || (padlen + len) < 16) {
		padlen++;
	}

	return padlen;
}

/*
==================
Message::Add
==================
*/
void Message::Add(ubyte ub) {
	payload.push_back(ub);
}

void Message::AddUI(uint32 ui) {
	ubyte *ub = (ubyte*)&ui;
	payload.push_back(ub[3]);
	payload.push_back(ub[2]);
	payload.push_back(ub[1]);
	payload.push_back(ub[0]);
}

void Message::Add(string s) {
	for (unsigned i=0; i<s.length(); i++) {
		payload.push_back(s[i]);
	}
}

void Message::Add(const ubyte *c, int len) {
	for (unsigned i=0; i<len; i++) {
		payload.push_back(c[i]);
	}
}

void Message::Add(MPInt &mpint) {
	// TODO
}


// ======================================================


/*
==================
NameList::NameList
==================
*/
NameList::NameList() {

}

/*
==================
NameList::NameList
==================
*/
NameList::NameList(const ubyte *raw, uint32 len, int &myLen) {
	SetFromRaw(raw, len, myLen);
}

/*
==================
NameList::payload

When payloading from a raw received packet, "raw" should
point to the start of the name-list. "len" should be the 
REMAINDING length of the packet. "myLen" is set to the TOTAL
length of the name-list.
==================
*/
void NameList::SetFromRaw(const ubyte *raw, uint32 len, int &myLen) {
	uint32 num;						// Number of bytes in list
	uint32 b = sizeof(uint32);		// Bytes traversed
	uint32 lasti = b; 				// Start of last name

	BytesToInt(num, raw);

	// Copy the the first N-1 elements into the vector
	for (unsigned i=0; i<num; i++) {
		if (raw[b+i] == ',') {
			char *name = new char[b+i-lasti];
			memcpy(name, raw+lasti, b+i-lasti);

			string strName = name;
			names.push_back(strName);

			lasti = b+i+1;
			delete[] name;
		}
	}

	// Copy the Nth element into the vector
	char *name = new char[b+num-lasti];
	memcpy(name, raw+lasti, b+num-lasti);

	string strName = name;
	names.push_back(strName);

	delete[] name;

	// "num" does not include its own length
	myLen = num + sizeof(uint32);
}

/*
==================
NameList::GetString
==================
*/
string NameList::GetString() {
	uint32 len = 0;

	string tempString;
	for (unsigned i=0; i<names.size(); i++) {
		tempString += names[i];
		len += names[i].length();

		if (i < names.size()-1) {
			tempString += ",";
			len++;
		}
	}

	stringstream ss;

	ubyte *blen = (ubyte*)&len;
	ss <<blen[3] <<blen[2] <<blen[1] <<blen[0];
	ss <<tempString;

	return ss.str();
}

/*
==================
NameList::Display
==================
*/
void NameList::Display() {
	printf("Name-list:\n");
	for (unsigned i=0; i<names.size(); i++) {
		printf("\t%s\n", names[i].c_str());
		
		continue;
		
		printf("\t\t");
		for (unsigned j=0; j<names[i].length(); j++) {
			printf("%x ", names[i][j]);
		}
		printf("\n");
	}
}


// ======================================================


/*
==================
MPInt::MPInt
==================
*/
MPInt::MPInt() {
	leadingZero = false;
}

/*
==================
MPInt::~MPInt
==================
*/
MPInt::~MPInt() {
	
}

/*
==================
MPInt::SetFromRaw
==================
*/
uint32 MPInt::SetFromRaw(const ubyte *raw, uint32 packetlen) {
	len = 0;
	BytesToInt(len, raw);

	if (packetlen < len) {
		Warning("MPInt::SetFromRaw error: length mismatch.");
		len = 0;
		return 0;
	}

	mpz_import(mpz.get_mpz_t(), len, 0, 1, 0, 0, raw+4);

	return len + 4;
}

/*
==================
MPInt::GetRawLength
==================
*/
uint32 MPInt::GetRawLength() {
	ubyte offset = 0;

	uint32 nlen = mpz_sizeinbase(mpz.get_mpz_t(), 16);
	if (nlen % 2) {
		len++;
		offset++;
	}

	// Add a leading "0" to give an even lengthed string
	char str[nlen + 1];
	mpz_get_str(str+offset, 16, mpz.get_mpz_t());
	for (int i=0; i<offset; i++) {
		str[i] = 0;
	}

	/* IF THE HIGH ORDER BIT IS 1, THE
	 * NUMBER IS TECHNICALLY NEGATIVE, AND
	 * A LEADING ZERO MUST BE ADDED. 
	 */
	if (!leadingZero) {
		char c[2] = { str[offset], 0 };
		if (strtol(c, NULL, 16) & 8) { 
			printf("ZERO OVERRIDE\n");
			leadingZero = true;
		}
	}

	nlen /= 2;
	nlen += leadingZero;

	return nlen + 4;
}

/*
==================
MPInt::GetRawBytes
==================
*/
void MPInt::GetRawBytes(ubyte *buffer) {
	char *str;
	char tmp[3] = {0, 0, 0};
	ubyte offset = 0;
	uint32 len;

	memset(buffer, 0, 10);

	// Get the length of the number in HEX
	len = mpz_sizeinbase(mpz.get_mpz_t(), 16);
	if (len % 2) {
		len++;
		offset++;
	}

	// Add a leading "0" to give an even lengthed string
	str = new char[len + 1];
	mpz_get_str(str+offset, 16, mpz.get_mpz_t());
	for (int i=0; i<offset; i++) {
		str[i] = 0;
	}

	// Copy the string into the data-array
	for (int i=0; i<len/2; i++) {
		tmp[0] = str[i*2];
		tmp[1] = str[i*2+1];

		buffer[i+4+leadingZero] = (ubyte)strtol(tmp, NULL, 16);
	}

	// Fill in the length field
	uint32 bytelen = len/2 + leadingZero;
	ubyte *bytes = (ubyte*)&bytelen;

	buffer[0] = bytes[3];
	buffer[1] = bytes[2];
	buffer[2] = bytes[1];
	buffer[3] = bytes[0];

	delete[] str;
}


// ======================================================


/*
==================
DSSBlob::DSSBlob
==================
*/
DSSBlob::DSSBlob() {
	rawLen = 0;
	raw = NULL;
}

/*
==================
DSSBlob::~DSSBlob
==================
*/
DSSBlob::~DSSBlob() {
	if (raw) {
		delete[] raw;
	}
}

/*
==================
DSSBlob::SetFromRaw
==================
*/
uint32 DSSBlob::SetFromRaw(const ubyte *packet, uint32 paclen) {
	uint32 b=0;		// Byte iterator
	uint32 len=0;	// DSS-field length
	uint32 flen=0;	// Field length
	char *kstr=0; 	// Identifity string (should be "ssh-dss")

	/* Copy the raw data */
	BytesToInt(len, packet);
	b += sizeof(uint32);

	rawLen = len+4;
	raw = new ubyte[rawLen];
	memcpy(raw, packet, rawLen);

	if (paclen < len) {
		Error("DSSBlob::SetFromRaw() : " 
			   "subfield is shorter than packet length.");
		return 0;
	}

	BytesToInt(flen, packet+b);
	b += sizeof(uint32);

	kstr = new char[flen+1];
	kstr[flen] = 0;
	memcpy(kstr, packet+b, flen);
	if (strcmp(kstr, "ssh-dss") != 0) {
		printf("Expected ssh-dss, got %s.\n", kstr);
		delete[] kstr;
		return 0;
	}
	delete[] kstr;
	b += flen;

	uint32 tmplen = 0;

	lenp = p.SetFromRaw(packet+b, paclen);
	b += lenp;
	p.leadingZero = true;

	lenq = q.SetFromRaw(packet+b, paclen);
	b += lenq;

	leng = g.SetFromRaw(packet+b, paclen);
	b += leng;
	g.leadingZero = true;

	leny = y.SetFromRaw(packet+b, paclen);
	b += leny;

	return len + 4;
}


// ======================================================


/*
==================
Packet::Packet
==================
*/
Packet::Packet(const ubyte *raw, uint32 len) {
	uint32 b = 0; 			// Byte iterator@

	BytesToInt(packetLength, raw);
	b += sizeof(uint32);

	paddingLength = raw[b++];
	type = raw[b++];

	/* "packetLength" contains the length of the
	 * payload field, the "paddingLength" and "padding"
	 * fields. At "packetLength+4", we should find the
	 * MAC. */
	b = packetLength + 4;
	if (b + 20 == len) {
		memcpy(mac, raw+b, 20);
	} else {
		memset(mac, 0, 20);
		if (len - b != 0) {
			//printf("len: %i  packetlen: %i  b: %i\n", len, packetLength, b);
			//Warning("Packet: Length mismatch", len-b);
		}
	}
}

/*
==================
Packet::IsOfType
==================
*/
bool Packet::IsOfType(ubyte ty) {
	return (type == ty);
}


// ======================================================


/*
==================
KexPacket::KexPacket
==================
*/
KexPacket::KexPacket(const ubyte *raw, int len) 
: Packet(raw, len) {
	uint32 b = 6; 			// Bytes traversed
	int nlLen = 0;			// Name-list length

	if (type != SSH_MSG_KEXINIT) {
		Warning("Expected SSH_MSG_KEXINIT", type);
		return;
	}

	memcpy(cookie, raw+b, 16);
	b += 16;

	// payload the name-lists
	kexAlgo.SetFromRaw(raw+b, len-b, nlLen);
	b += nlLen;

	serverHostKeyAlgo.SetFromRaw(raw+b, len-b, nlLen);
	b += nlLen;

	encrypt_clientServer.SetFromRaw(raw+b, len-b, nlLen);
	b += nlLen;

	encrypt_serverClient.SetFromRaw(raw+b, len-b, nlLen);
	b += nlLen;

	mac_clientServer.SetFromRaw(raw+b, len-b, nlLen);
	b += nlLen;

	mac_serverClient.SetFromRaw(raw+b, len-b, nlLen);
	b += nlLen;

	comp_clientServer.SetFromRaw(raw+b, len-b, nlLen);
	b += nlLen;

	comp_serverClient.SetFromRaw(raw+b, len-b, nlLen);
	b += nlLen;

	lang_clientServer.SetFromRaw(raw+b, len-b, nlLen);
	b += nlLen;

	lang_serverClient.SetFromRaw(raw+b, len-b, nlLen);
	b += nlLen;

	firstKexFollows = raw[b++];

	BytesToInt(reserved, raw+b);
	b += sizeof(uint32);

	b += paddingLength;

	//printf("First kex follows: %i\n", firstKexFollows);
	//printf("Reserved: %u\n", reserved);
	//printf("Unread bytes: %i\n", len-b);
	if (len-b != 0) {
		Warning("KexPacket: Length mismatch", len-b);
	}
}


// ======================================================


/*
==================
KexDHPacket::KexDHPacket
==================
*/
KexDHPacket::KexDHPacket(const ubyte *raw, uint32 len) 
: Packet(raw, len) {
	uint32 b = 6; 		// Byte iterator
	uint32 flen = 0;	// Field length
	char *kstr=0; 		// Identity string

	if (IsOfType(SSH_MSG_KEXDH_REPLY)) {
		printf("Received SSH_MSG_KEXDHREPLY\n");
	} else {
		Warning("KexDHPacket(): Bad packet data given!");
		return;
	}

	/* Read the dss blob */
	if (GData::dssBlob) {
		delete GData::dssBlob;
	}

	GData::dssBlob = new DSSBlob();
	b += GData::dssBlob->SetFromRaw(raw+b, len);

	/* Read the F value */
	rawFlen = dhF.SetFromRaw(raw+b, len);
	rawF = new ubyte[rawFlen];
	memcpy(rawF, raw+b, rawFlen);
	b += rawFlen;

	/* Copy the entire public-key field */
	BytesToInt(flen, raw+b);
	b += sizeof(uint32);

	// The identification string must be "ssh-dss"
	BytesToInt(flen, raw+b);
	b += sizeof(uint32);
	kstr = new char[flen+1];
	kstr[flen] = 0;
	memcpy(kstr, raw+b, flen);
	if (strcmp(kstr, "ssh-dss") != 0) {
		printf("KexDHPacket: Expected ssh-dss, got %s.\n", kstr);
		delete[] kstr;
		return;
	}

	delete[] kstr;
	b += flen;

	/* Read the signature blob */
	BytesToInt(flen, raw+b);
	b += sizeof(uint32);

	if (flen != 40) {
		/* TODO: Disconnect here */
		stringstream ss;
		ss <<"DSA signature-blob length mismatch! ";
		ss <<"Expected 40 bytes, got " <<flen <<"!";
		Error(ss.str().c_str());
		return;
	}

	memcpy(dssR, raw+b, 20);
	b += 20;

	memcpy(dssS, raw+b, 20);
	b += 20;

	b += paddingLength;

	/* The SSH_MSG_NEWKEYS packet follows: */
	if (len - b > 8) {
		Packet p(raw+b, len-b);
		if (p.IsOfType(SSH_MSG_NEWKEYS)) {
			printf("Received SSH_MSG_NEWKEYS\n");
		} else {
			Warning("Dit not receive SSH_MSG_NEWKEYS!");
		}
	} else {
		Warning("Dit not receive SSH_MSG_NEWKEYS!");
	}
}

/*
==================
KexDHPacket::~KexDHPacket
==================
*/
KexDHPacket::~KexDHPacket() {
	delete[] rawF;
}