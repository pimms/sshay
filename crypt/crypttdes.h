#pragma once

#include <openssl/des.h>
#include "../sshay.h"

class Session;

class CryptTDES {
public:
				CryptTDES();
	virtual 	~CryptTDES();

	ubyte*		Encrypt(const ubyte *data, uint32 len);
	ubyte*		Decrypt(const ubyte *data, uint32 len);

private:
	friend class Session;
	
	ubyte 		keyEnc[24];
	ubyte 		keyDec[24];

	ubyte 		ivEnc[8];	// Working vector for encryption
	ubyte 		ivDec[8];	// Working vector for decryption

	ubyte 		*lastEnc;	// Last encoded message
	ubyte 		*lastDec;	// Last decoded message

	/* Decrypt or encrypt */
	ubyte* 		Xcrypt(const ubyte*, uint32, int direction);
};

