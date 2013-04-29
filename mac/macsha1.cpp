#include "macsha1.h"
#include <openssl/sha.h>

/*
==================
MacSHA1::MacSHA1
==================
*/
MacSHA1::MacSHA1() {
	lptr = NULL;
}

/*
==================
MacSHA1::~MacSHA1
==================
*/
MacSHA1::~MacSHA1() {
	if (lptr) {
		delete[] lptr;
	}
}

/*
==================
MacSHA1::GetHash
==================
*/
ubyte* MacSHA1::GetHash() {
	if (lptr) {
		delete[] lptr;
	}

	ubyte *input = new ubyte[buffer.size()];
	copy(buffer.begin(), buffer.end(), input);

	lptr = new ubyte[20];

	SHA1(input, buffer.size(), lptr);

	delete[] input;
	return lptr;
}

/*
==================
MacSHA1::GetBuffer
==================
*/
ubyte* MacSHA1::GetBuffer() {
	if (lptr) {
		delete[] lptr;
	}

	lptr = new ubyte[buffer.size()];
	copy(buffer.begin(), buffer.end(), lptr);

	return lptr;
}

/*
==================
MacSHA1::GetBufferLength
==================
*/
int MacSHA1::GetBufferLength() {
	return buffer.size();
}

/*
==================
MacSHA1::Clear
==================
*/
void MacSHA1::Clear() {
	buffer.clear();
}

/*
==================
MacSHA1::Add
==================
*/
void MacSHA1::Add(string str) {
	for (int i=0; i<str.length(); i++) {
		buffer.push_back((ubyte)str[i]);
	}
}

void MacSHA1::Add(byte b) {
	buffer.push_back((ubyte)b);
}

void MacSHA1::Add(ubyte ub) {
	buffer.push_back(ub);
}

void MacSHA1::Add(ubyte *ub, uint32 len) {
	for (int i=0; i<len; i++) {
		buffer.push_back(ub[i]);
	}
}

void MacSHA1::AddUI(uint32 ui) {
	ubyte *ptr = (ubyte*)&ui;

	buffer.push_back(ptr[3]);
	buffer.push_back(ptr[2]);
	buffer.push_back(ptr[1]);
	buffer.push_back(ptr[0]);
}