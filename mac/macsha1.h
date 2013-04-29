#pragma once

#include <openssl/sha.h>
#include "../sshay.h"

class MacSHA1 {
public:
					MacSHA1();
					~MacSHA1();
	ubyte*			GetHash();
	ubyte* 			GetBuffer();
	int 			GetBufferLength();
	void 			Clear();

	void 			Add(string str);
	void 			Add(byte b);
	void 			Add(ubyte ub);
	void 			Add(ubyte *ub, uint32 len);
	void 			AddUI(uint32 ui);
	
private:
	vector<ubyte> 	buffer;
	ubyte 			*lptr;
};