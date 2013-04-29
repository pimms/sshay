#pragma once

#include "../sshay.h"
#include "../mac/macsha1.h"
#include "../net/socket.h"
#include "../prot/packet.h"
#include <openssl/dsa.h>

enum DHType {
	DH_GROUP1,		// Use Oakley group 2
	DH_GROUP14,		// Use Oakley group 14 (UNSUPPORTED)
};

/*
==================
KeyExchange

The KeyExchange class uses Diffie-Hellman. It is 
expected that when the KeyExchange is initiated via
the "Init" method, the connection has been setup and
that the KEXINIT packets have been sent and received
by both parties.
==================
*/
class KeyExchange {
public:
				KeyExchange();
				~KeyExchange();

	void 		Init(DHType, Socket*);

	/* Protocol methods */
	bool 		SendDHInit();
	bool 		VerifyDHReply();

private:
	Socket 		*socket;
	DHType 		dhtype;
	bool 		isInitiated;

	DSA 		*dsakey;
	DSA_SIG 	*dsasig;

	MPInt 		dhP;	// The stupidly high prime
	MPInt 		dhG;	// The generator
	MPInt 		dhX;	// The random number
	MPInt 		dhE;	// dhG^dhX % dhP

	void 		CalculateSharedSecret();
	void 		CalculateDHReplyHash(ubyte *hashBuf);
	bool 		VerifyDHReplyHash(ubyte *hash);

	bool 		SetDHParams();

	/* Message generators */
	Message 	GetDHInitMessage();
};


// ============================================= //
// The number defined below are the responses    //
// received in the KEXDH_REPLY packet sent from  //
// an OpenSSH-server with DH-group1 as KEX-algo. //
// The number could be (read: probably are) way  //
// off what is expected. I was not able to       //
// verify the integrity of these numbers.        //
// This is a dangerous assumption.               //
// ============================================= //

#define MODP_OAK2								   \
"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" \
"FFFFFFFFFFFFFFFF"
#define MODP_OAK14 								   \
"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
"83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" \
"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" \
"15728E5A8AACAA68FFFFFFFFFFFFFFFF"

#define GEN_OAK2	"2"
#define GEN_OAK14 	"2"