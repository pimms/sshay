#include "unittest.h"
#include "../prot/packet.h"
#include "../sshay.h"

#define __TEST_TYPE "SSH Types"

bool UT__mpintFromRaw() {
	/* Ensure that you can initialize an MPInt from
	 * raw, binary data and get the correct output
	 * every time. */
	ubyte raw[] = {
		0x00, 0x00, 0x00, 0x08,		// Length
		0x0F, 0x42, 0xFF, 0x00,
		0xAE, 0x54, 0xF0, 0x00
	};

	/* The decimal version of "raw" */
	char decimal[] = "1099721637421707264";

	MPInt mpint;
	mpint.SetFromRaw(raw, 12);

	mpz_class f(decimal);

	if (f != mpint.mpz) {
		return false;
	}

	if (mpint.len != 8) {
		return false;
	}

	return true;
}

bool UT__mpintRawToMpintToRaw() {
	/* Is it safe to dance? */
	ubyte dummy[] = {
		0x00, 0x00, 0x00, 0x09,
		0x2A, 0xFE, 0x71, 0x00,
		0xDA, 0x0C, 0xE0, 0x54,
		0xFF,
	};

	MPInt mpint;
	mpint.SetFromRaw(dummy, 13);


	/* The returned raw data must be identical
	 * to dummy[], and of length 13. */
	uint32 len = mpint.GetRawLength();
	if (len != 13) {
		return false;
	}

	ubyte *buf = new ubyte[len];
	mpint.GetRawBytes(buf);

	for (uint32 i=0; i<len; i++) {
		if (dummy[i] != buf[i]) {
			return false;
		}
	}

	/* Use the raw output to initialize a new MPInt */
	MPInt mpint2;
	mpint2.SetFromRaw(buf, len);
	if (mpint2.mpz != mpint.mpz) {
		return false;
	}

	return true;
}

bool UT__messageLen() {
	/* The total length of the packet must be:
	 *   4 + 1 + 22 + 5 = 32
	 */
	string str = "eplefjes og tur i mark"; // strlen == 22
	Message msg;
	uint32 len;
	uint32 padlen;
	ubyte *data;

	msg.Add(str);

	len = msg.GetLength();
	padlen = msg.GetPaddingLength();

	if (padlen != 5) {
		return false;
	}

	if (len != 22 + 5 + 5) {
		return false;
	}

	data = msg.GetData();
	
	BytesToInt(len, data);
	if (len != 28) {
		return false;
	}

	if (data[4] != 5) {
		return false;
	}

	return true;
}

void UT_Types() {
	UNIT_TEST(UT__mpintFromRaw, "MPInt initialization from raw");
	UNIT_TEST(UT__mpintRawToMpintToRaw, "MPInt raw-rotation");
	UNIT_TEST(UT__messageLen, "Message lengths");
}