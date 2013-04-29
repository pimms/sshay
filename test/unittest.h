#pragma once

#include <sstream>

#define UNIT_TEST(_UT_FUNC_, _DESC_) 					\
	printf("Testing %s: %s...\n", __TEST_TYPE, _DESC_); \
	if (!_UT_FUNC_()) { 								\
		std::stringstream __ss;							\
		__ss << "Unit test failed (" <<#_UT_FUNC_  		\
		   	 <<"):\n\t" <<#_DESC_;						\
		Critical(__ss.str().c_str());					\
	}

/* Defined in packettest.cpp */
void UT_Packet();

/* Defined in typetest.cpp */
void UT_Types();

/* Defined in mactest.cpp */
void UT_Mac();

/* Defined in dsstest.cpp */
void UT_DSS();