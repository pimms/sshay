#include "crypttdes.h"


/*
==================
CryptTDES::CryptTDES
==================
*/
CryptTDES::CryptTDES() {
	memset(keyEnc, 0, 24*sizeof(ubyte));
	memset(keyDec, 0, 24*sizeof(ubyte));

	ubyte tmp[] = {1,2,3,4,5,6,7,8};
	memcpy(ivEnc, tmp, 8);
	memcpy(ivDec, tmp, 8);

	lastEnc = NULL;
	lastDec = NULL;
}

/*
==================
CryptTDES::~CryptTDES
==================
*/
CryptTDES::~CryptTDES() {
	if (lastEnc) {
		delete[] lastEnc;
	}

	if (lastDec) {
		delete[] lastDec;
	}
}

/*
==================
CryptTDES::Encrypt
==================
*/
ubyte* CryptTDES::Encrypt(const ubyte *raw, uint32 len) {
	if ((len % 8) != 0) {
		Error("Attempt to encrypt data where \"length != x*8\"!");
		return NULL;
	}

	if (lastEnc) {
		delete[] lastEnc;
		lastEnc = NULL;
	}

	lastEnc = Xcrypt(raw, len, DES_ENCRYPT);

	return lastEnc;
}

/*
==================
CryptTDES::Decrypt
==================
*/
ubyte* CryptTDES::Decrypt(const ubyte *raw, uint32 len) {
	if ((len % 8) != 0) {
		Error("Attempt to decrypt data where \"length != x*8\"!");
		return NULL;
	}

	if (lastDec) {
		delete[] lastDec;
		lastDec = NULL;
	}

	lastDec = Xcrypt(raw, len, DES_DECRYPT);
	return lastDec;
}

/*
==================
CryptTDES::Xcrypt
==================
*/
ubyte* CryptTDES::Xcrypt(const ubyte *data, uint32 len, 
							int dir) {
	ubyte (*workVec)[8];
	ubyte key[3][8];
	ubyte *result = new ubyte[len];
	DES_key_schedule ks1, ks2, ks3;

	if (dir == DES_ENCRYPT) {
		workVec = &ivEnc;
		
		memcpy(key[0], keyEnc +  0, 8);
		memcpy(key[1], keyEnc +  8, 8);
		memcpy(key[2], keyEnc + 16, 8);
	} else if (dir == DES_DECRYPT) {
		workVec = &ivDec;
		
		memcpy(key[0], keyDec +  0, 8);
		memcpy(key[1], keyDec +  8, 8);
		memcpy(key[2], keyDec + 16, 8);
	} else {
		Error("Unknown cipher direction", dir);
		delete[] result;
		return NULL;
	}

	DES_set_key(&key[0], &ks1);
	DES_set_key(&key[1], &ks2);
	DES_set_key(&key[2], &ks3);

	for (int i=0; i<len/8; i++) {
		ubyte tmpRes[8];

		DES_ede3_cbc_encrypt(
			data+i*8, tmpRes, 8,
			&ks1, &ks2, &ks3, 
			workVec, dir
		);

		memcpy(result+i*8, tmpRes, 8);
	}

	return result;
}