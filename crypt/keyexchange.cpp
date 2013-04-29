#include "keyexchange.h"
#include "../prot/session.h"
#include "../mac/macsha1.h"
#include "../globdata.h"
#include <sys/time.h>
#include <openssl/dsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/*
==================
KeyExchange::KeyExchange
==================
*/
KeyExchange::KeyExchange() {
	isInitiated 	= false;

	dsasig 	  		= DSA_SIG_new();
	dsasig->r 		= BN_new();
	dsasig->s 		= BN_new();

	dsakey 	  		= DSA_new();
	dsakey->p 		= BN_new();
	dsakey->q 		= BN_new();
	dsakey->g 		= BN_new();
	dsakey->pub_key = BN_new();
}

/*
==================
KeyExchange::~KeyExchange
==================
*/
KeyExchange::~KeyExchange() {
	DSA_free(dsakey);
	DSA_SIG_free(dsasig);
}

/*
==================
KeyExchange::Init
==================
*/
void KeyExchange::Init(DHType type, Socket *so) {
	socket = so;
	dhtype = type;

	if (!socket->IsConnected()) {
		Critical("Could not start KEXDH - socket disconnected");
	}

	SetDHParams();

	isInitiated = true;
}

/*
==================
KeyExchange::SendDHInit
==================
*/
bool KeyExchange::SendDHInit() {
	if (!isInitiated) {
		Error("Cannot send KEXDH_INIT: Not initiated\n");
		return false;
	}

	Message msg = GetDHInitMessage();
	if (!socket->Write(msg.GetData(), msg.GetLength())) {
		return false;
	}

	printf("Sent KEXDH_INIT\n");
	return true;
}

/*
==================
KeyExchange::VerifyDHReply
==================
*/
bool KeyExchange::VerifyDHReply() {
	if (!isInitiated) {
		Warning("KeyExchange::VerifyDHReply(): "
				"NOT initiated!!!!");
	}

	ubyte *data = socket->Read();

	if (socket->LastSize() >= 6) {
		if (data[5] != 31) {
			printf("Expected 31, got %i\n", data[5]);
			return false;
		} 
	} else {
		return false;
	}

	GData::dhReply = new KexDHPacket(data, socket->LastSize());
	if (!GData::dhReply->IsOfType(SSH_MSG_KEXDH_REPLY)) {
		return false;
	}

	if (GData::dhReply->dhF.mpz < 1 
	||  GData::dhReply->dhF.mpz >= dhP.mpz) {
		printf("Invalid F-value\n");
		return false;
	}

	CalculateSharedSecret();

	ubyte hash[20];
	CalculateDHReplyHash(hash);
	
	if (!VerifyDHReplyHash(hash)) {
		return false;
	}

	return true;
}

/*
==================
KeyExchange::CalculateSharedSecret
==================
*/
void KeyExchange::CalculateSharedSecret() {
	if (!GData::dhReply) { 
		Error("Cannot calculate shared secret without F!");
		return;
	}

	if (GData::sharedSecret) {
		delete GData::sharedSecret;
	}

	GData::sharedSecret = new MPInt;

	mpz_powm(
		GData::sharedSecret->mpz.get_mpz_t(),
		GData::dhReply->dhF.mpz.get_mpz_t(),
		dhX.mpz.get_mpz_t(),
		dhP.mpz.get_mpz_t()
	);

	//gmp_printf("Shared:\n%Zx\n\n", dhK.get_mpz_t());
}

/*
==================
KeyExchange::CalculateDHReplyHash

The hash is calculated from the following values:
	string    V_C, the client's identification string (CR and LF
	          excluded)
	string    V_S, the server's identification string (CR and LF
	          excluded)
	string    I_C, the payload of the client's SSH_MSG_KEXINIT
	string    I_S, the payload of the server's SSH_MSG_KEXINIT
	string    K_S, the host key
	mpint     e, exchange value sent by the client
	mpint     f, exchange value sent by the server
	mpint     K, the shared secret
==================
*/
void KeyExchange::CalculateDHReplyHash(ubyte *hashBuf) {
	if (!GData::dhReply) return;

	uint32 len = 0;
	ubyte *buf = 0;

	/* We're not using "mac" to hash, but to store
	 * the data. Sorry for the confusion. */
	MacSHA1 mac;
	
	string V_C;
	string V_S;
	/* I_C: session->lKexinitPl */
	/* I_S: session->rKexinitPl */
	/* K_S: kexDH->dss.y */
	/* mpint e: dhE */
	/* mpint f: kexDH->mpF.mpz */
	/* mpint k: dhK */

	V_C = GData::localid;
	V_C = V_C.substr(0, V_C.length()-2);
	mac.AddUI(V_C.length());
	mac.Add(V_C);

	V_S = GData::remoteid;
	mac.AddUI(V_S.length());
	mac.Add(V_S);

	mac.AddUI(GData::localKexinitlen);
	mac.Add(GData::localKexinit, GData::localKexinitlen);

	mac.AddUI(GData::remoteKexinitlen);
	mac.Add(GData::remoteKexinit, GData::remoteKexinitlen);

	/* PUBLIC KEY */
	mac.Add(GData::dssBlob->raw, GData::dssBlob->rawLen);

	/* MPINTS */
	len = dhE.GetRawLength();
	buf = new ubyte[len];
	dhE.GetRawBytes(buf);
	mac.Add(buf, len);
	delete[] buf;
	//printf("E len: %i\n", len-4);

	len = GData::dhReply->rawFlen;
	mac.Add(GData::dhReply->rawF, len);
	//printf("F len: %i\n", len-4);

	/* TO DO: 
	 * Find the correlation between leading zero
	 * in the shared secret and E+F. 
	 */
	MPInt *dhK = GData::sharedSecret;
	//dhK->leadingZero = GData::dhReply->rawFlen == 133;

	len = dhK->GetRawLength();
	buf = new ubyte[len];
	dhK->GetRawBytes(buf);
	mac.Add(buf, len);
	delete[] buf;
	//printf("K len: %i\n", len-4);

	/* Double hash the data, store the first hash */
	memcpy(hashBuf, mac.GetHash(), 20);
	memcpy(GData::exchangeHash, hashBuf, 20);

	/* Print the raw data */
	/*
	printf("Raw hash buffer: \n\t");
	ubyte *rawbuf = mac.GetBuffer();
	for (int i=0; i<mac.GetBufferLength(); i++) {
		printf("%s%x ", rawbuf[i]<0x10?"0":"", rawbuf[i]);
		if (!(i%32)) {
			printf("\n\t");
		}
	}
	printf("\n\n\n");
	*/

	mac.Clear();
	mac.Add(hashBuf, 20);
	memcpy(hashBuf, mac.GetHash(), 20);
}

/*
==================
KeyExchange::VerifyDHReplyHash

"myHash" is the hash calculated by "CalculateDHReplyHash()".
==================
*/
bool KeyExchange::VerifyDHReplyHash(ubyte *myHash) {
	if (BN_bin2bn(GData::dhReply->dssR, 20, dsasig->r) == 0) {
		printf("Failed to set dsasig->r\n");
		return false;
	}

	if (BN_bin2bn(GData::dhReply->dssS, 20, dsasig->s) == 0) {
		printf("Failed to set dsasig->s\n");
		return false;
	}

	/* Set the DSS P, Q, G and Y values */
	MPInt *src[4] = { 
		&GData::dssBlob->p, 	&GData::dssBlob->q,
		&GData::dssBlob->g, 	&GData::dssBlob->y };
	BIGNUM *dst[4] = {
		dsakey->p, 				dsakey->q,
		dsakey->g, 				dsakey->pub_key };

    for (int i=0; i<4; i++) {
    	uint32 len = src[i]->GetRawLength();
    	ubyte *raw = new ubyte[len];
    	src[i]->GetRawBytes(raw);

    	if (BN_bin2bn(raw+4, len-4, dst[i]) == 0) {
    		printf("Failed to set dsakey->[%i]\n", i);
    		delete[] raw;
    		return false;
    	}

    	delete[] raw;
    }

    int result = 0;
    result = DSA_do_verify(myHash, 20, dsasig, dsakey);

	if (result == 0) {
		Warning("Signature verification failed.");

		printf("Failed to verify the identity of the server.\n");
		printf("The connection is NOT secure!!!!\n");
		printf("Would you like to continue anyway? (y/N)  ");
		string in;
		getline(cin, in);

		if (in.length() == 1 && toupper(in[0]) == 'Y') {
			printf("Continuing with an insecure connection.\n");
			printf("\tUbw5N8iVDHI\n");
			return true;
		}

		return false;
	} else if (result == -1) {
		Error("An error occurred when verifying signature");
		BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
		ERR_print_errors(bio);
		BIO_free(bio);
		return false;
	} else if (result == 1) {
		/* Everything went WAY better than expected */
		printf("DSA Signature verified!\n");
		return true;
	}

	Critical("KeyExchange::VerifyDHReplyHash(): \n\t"
			 "DSA_do_verify returned something "
			 "exceptionally wrong!");
}

/*
==================
KeyExchange::SetDHParams
==================
*/
bool KeyExchange::SetDHParams() {
	/* Set the known parameters */
	if (dhtype == DH_GROUP1) {
		dhP.mpz.set_str(MODP_OAK2, 16);
		dhG.mpz.set_str(GEN_OAK2, 16);
	} else if (dhtype == DH_GROUP14) {
		dhP.mpz.set_str(MODP_OAK14, 16);
		dhG.mpz.set_str(GEN_OAK14, 16);
	} else {
		Critical("Unkown DH-group!");
	}

	/* Calculate a random X up to 159 bits */
	gmp_randclass ran(gmp_randinit_default);

	struct timeval tp;
	gettimeofday(&tp, NULL);
	ran.seed(tp.tv_sec + tp.tv_usec);

	MPInt dhQ;
	dhQ.mpz = (dhP.mpz-1) / 2;

	do {
		dhX.mpz = 0;
		while ((dhX.mpz <= 1 || dhX.mpz >= dhQ.mpz)) {
			dhX.mpz = ran.get_z_bits(159);
		}

		// e = g^x % p
		mpz_powm(
			dhE.mpz.get_mpz_t(),
			dhG.mpz.get_mpz_t(),
			dhX.mpz.get_mpz_t(),
			dhP.mpz.get_mpz_t()
		);
	} while (dhE.mpz >= dhQ.mpz);
}

/*
==================
KeyExchange::GetDHInitMessage
==================
*/
Message KeyExchange::GetDHInitMessage() {
	if (dhE.mpz == 0) {
		Error("Cannot create DHINIT msg when dhE==0!");
		Message m;
		return m;
	}

	ubyte *data;
	uint32 len;
	Message msg;

	len = dhE.GetRawLength();
	data = new ubyte[len];
	dhE.GetRawBytes(data);

	msg.Add((ubyte)SSH_MSG_KEXDH_INIT);
	msg.Add(data, len);
	delete[] data;

	return msg;
}