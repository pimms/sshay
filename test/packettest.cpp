#include "unittest.h"
#include "../prot/packet.h"

#define __TEST_TYPE "Packet"

bool UT__ReadDefaultPacketData() {
	ubyte dummypacket[] = {
		0x0, 0x0, 0x0, 0x6,		// Packet length
		0x4, 0x0,				// Padding length and type
		0x1, 0x2, 0x3, 0x4, 	// Padding
		0x0, 0x0, 0x0, 0x0,		// MAC
		0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0,
	};

	Packet p(dummypacket, 30);

	if (p.packetLength != 6) {
		return false;
	}

	if (p.paddingLength != 4) {
		return false;
	}

	if (p.type != 0) {
		return false;
	}

	for (unsigned i=0; i<20; i++) {
		if (p.mac[i] != 0) {
			return false;
		}
	}

	if (!p.IsOfType(0)) {
		return false;
	}

	return true;
}

bool UT__MessageCreation() {
	Message msg;

	msg.Add((ubyte)30);
	msg.Add("This is my payload. There are many like it, but ");
	msg.Add("this one is mine. Without my packet, my payload ");
	msg.Add("is nothing. Without my payload, my packet is nothing.");

	ubyte *data = msg.GetData();
	uint32 len;
	BytesToInt(len, data);

	if (msg.GetLength() != len+4) {
		return false;
	}

	if (data[5] != 30) {
		return false;
	}

	return true;
}

void UT_Packet() {
	UNIT_TEST(UT__ReadDefaultPacketData, "Read default packet data")
	UNIT_TEST(UT__MessageCreation, "Message creation")
}