#include <pthread.h>
#include <assert.h>

#include "sshay.h"
#include "net/socket.h"
#include "prot/packet.h"
#include "prot/session.h"
#include "test/unittest.h"
#include "globdata.h"

void Warning(const char *msg) {
	printf("%s[WARNING]: %s%s\n", CRED, msg, CWHITE);
}
void Warning(const char *msg, int wid) {
	printf("%s[WARNING](%i): %s%s\n", CRED, wid, msg, CWHITE);
}

void Error(const char *msg) {
	printf("%s[ERROR]: %s%s\n", CRED, msg, CWHITE);
}
void Error(const char *msg, int eid) {
	printf("%s[ERROR](%i): %s%s\n", CRED, eid, msg, CWHITE);
}

void Critical(const char *msg) {
	printf("%s[CRITICAL ERROR]: %s\n", CRED, msg);
	printf("[CRITICAL ERROR]: Shutting down!%s\n", CWHITE);
	exit(1);
}
void Critical(const char *msg, int eid) {
	printf("%s[CRITICAL ERROR](%i): \n", CRED, eid, msg);
	printf("[CRITICAL ERROR]: Shutting down!%s\n", CWHITE);
	exit(eid);
}

void DetermineHost(int argc, char *argv[], string &host, int &port) {
	port = 22;
	host = "localhost";

	if (argc >= 2) {
		host = argv[1];

		if (argc == 3) {
			port = atoi(argv[2]);
		} else {
			for (unsigned i = 0; i < host.length(); i++) {
				if (host[i] == ':') {
					const char *pstr = host.c_str() + i + 1;
					port = atoi(pstr);

					host = host.substr(0, i);
					return;
				}
			}
		}
	} else {
		Warning("No host specified! Using localhost");
	}
}

void GetTermDim(uint32 &chW, uint32 &chH, uint32 &pW, uint32 &pH) {
	struct winsize w;
    int ret;

   	ret = ioctl(0, TIOCGWINSZ, &w);

   	if (ret == -1) {
   		Error("Failed to get window size", errno);
   		chW = chH = pW = pH = 0;
   		return;
   	}

    chW = w.ws_row;
    chH = w.ws_col;
    pW  = w.ws_xpixel;
    pH  = w.ws_ypixel;
}

void HexDump(const ubyte *data, uint32 len, string s) {
	printf("%s:\n\t", s.c_str());
	for (uint32 i=0; i<len; i++) {
		printf("%s%x ", data[i]<0x10?"0":"", data[i]);
		if (i % 16 == 15) {
			printf("\n\t");
		} else {
			if (i % 8 == 7) {
				printf("  ");
			}
		}
	}
	printf("\n");
}

void SetStdinEcho(bool echo) {
	struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    
    if (!echo) {
        tty.c_lflag &= ~ECHO;
    } else {
        tty.c_lflag |= ECHO;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

int main(int argc, char *argv[]) {
	/* Perform unit-tests */
	printf("Performing unit-tests...\n");
	UT_Packet();
	UT_Types();
	UT_Mac();
	UT_DSS();
	printf("Unit-tests OK!\n\n");


	string host;
	int port;
	pthread_t serverThread;
	ubyte *data = NULL;
	int ret;

	DetermineHost(argc, argv, host, port);
	printf("Connecting to %s:%i...\n", host.c_str(), port);

	Session session;
	if (!session.Initiate(host, port)) {
		GData::Clear();
		return 1;
	}

	if (!session.UserAuthentication()) {
		GData::Clear();
		return 1;
	}

	ret = session.RunConnection();

	GData::Clear();
	return ret;
}