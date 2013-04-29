#include "unittest.h"
#include "../mac/macsha1.h"

#define __TEST_TYPE "Mac"

bool UT__MacString() {
	ubyte correct[20] = {
		0x2d, 0x4e, 0x51, 0xfe,
		0x54, 0x09, 0xad, 0x8a,
		0xb9, 0xcb, 0xb4, 0xbe,
		0x27, 0x0a, 0x40, 0xe1,
		0xf2, 0x25, 0xae, 0x1f,
	};

	MacSHA1 mac;
	mac.Add("eplefjes og tur i skog");

	ubyte test[20];
	memcpy(test, mac.GetHash(), 20);

	for (int i=0; i<20; i++) {
		if (test[i] != correct[i]) {
			return false;
		}
	}

	return true;
}

void UT_Mac() {
	UNIT_TEST(UT__MacString, "SHA-1 from string");
}