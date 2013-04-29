#pragma once

#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <cstring>
#include <sstream>
#include <errno.h>
#include <vector>
#include <gmpxx.h>

#define CRED  	"\e[0;31m"
#define CWHITE	"\e[0m"

#define MIN(A,B) (A<B?A:B)
#define MAX(A,B) (A>B?A:B)


using namespace std;

// ========================================================== //
// ==              All type definitions are                == //
// ==          taken directly from section 5 in            == //
// ==    http://www.snailbook.com/docs/architecture.txt    == //
// ========================================================== //
typedef char byte;
typedef unsigned char ubyte;
typedef unsigned int uint32;
typedef unsigned long int uint64;


/* Display a warning message. */
void Warning(const char *msg);
void Warning(const char *msg, int wid);

/* Display an error message. A more serious issue than "Warning" */
void Error(const char *msg);
void Error(const char *msg, int eid);

/* Display an error message and terminate the process. Super serious. */
void Critical(const char *msg);
void Critical(const char *msg, int eid);

/* Get the character and pixel dimensions of the terminal window */
void GetTermDim(uint32 &chW, uint32 &chH, uint32 &pW, uint32 &pH);

template <typename intTy>
intTy BytesToInt(intTy& result, const ubyte* bits, bool le=false) {
  result = 0;
  if (le) {
    for (int n = sizeof( result ); n >= 0; n--) {
      result = (result << 8) + bits[ n ];
    }
  } else {
    for (unsigned n = 0; n < sizeof( result ); n++) {
        result = (result << 8) + bits[ n ];
      }
  }
  return result;
}

void HexDump(const ubyte *data, uint32 len, string s);

void SetStdinEcho(bool echo=true);


// ========================================================== //
// ==         All descriptions, definitions and            == //
// ==        names following hereafter are taken           == //
// ==                    directly from                     == //
// ==  http://www.snailbook.com/docs/assigned-numbers.txt  == //
// ========================================================== //

/*
==================
Message ID Values
==================
*/
#define SSH_MSG_DISCONNECT                       1     //[SSH-TRANS]
#define SSH_MSG_IGNORE                           2     //[SSH-TRANS]
#define SSH_MSG_UNIMPLEMENTED                    3     //[SSH-TRANS]
#define SSH_MSG_DEBUG                            4     //[SSH-TRANS]
#define SSH_MSG_SERVICE_REQUEST                  5     //[SSH-TRANS]
#define SSH_MSG_SERVICE_ACCEPT                   6     //[SSH-TRANS]
#define SSH_MSG_KEXINIT                         20     //[SSH-TRANS]
#define SSH_MSG_NEWKEYS                         21     //[SSH-TRANS]
#define SSH_MSG_KEXDH_INIT                      30     // undef
#define SSH_MSG_KEXDH_REPLY                     31     // undef
#define SSH_MSG_USERAUTH_REQUEST                50     //[SSH-USERAUTH]
#define SSH_MSG_USERAUTH_FAILURE                51     //[SSH-USERAUTH]
#define SSH_MSG_USERAUTH_SUCCESS                52     //[SSH-USERAUTH]
#define SSH_MSG_USERAUTH_BANNER                 53     //[SSH-USERAUTH]
#define SSH_MSG_GLOBAL_REQUEST                  80     //[SSH-CONNECT]
#define SSH_MSG_REQUEST_SUCCESS                 81     //[SSH-CONNECT]
#define SSH_MSG_REQUEST_FAILURE                 82     //[SSH-CONNECT]
#define SSH_MSG_CHANNEL_OPEN                    90     //[SSH-CONNECT]
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION       91     //[SSH-CONNECT]
#define SSH_MSG_CHANNEL_OPEN_FAILURE            92     //[SSH-CONNECT]
#define SSH_MSG_CHANNEL_WINDOW_ADJUST           93     //[SSH-CONNECT]
#define SSH_MSG_CHANNEL_DATA                    94     //[SSH-CONNECT]
#define SSH_MSG_CHANNEL_EXTENDED_DATA           95     //[SSH-CONNECT]
#define SSH_MSG_CHANNEL_EOF                     96     //[SSH-CONNECT]
#define SSH_MSG_CHANNEL_CLOSE                   97     //[SSH-CONNECT]
#define SSH_MSG_CHANNEL_REQUEST                 98     //[SSH-CONNECT]
#define SSH_MSG_CHANNEL_SUCCESS                 99     //[SSH-CONNECT]
#define SSH_MSG_CHANNEL_FAILURE                100     //[SSH-CONNECT]


/*
==================
Disconnect codes
==================
*/
#define SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT          1
#define SSH_DISCONNECT_PROTOCOL_ERROR                       2
#define SSH_DISCONNECT_KEY_EXCHANGE_FAILED                  3
#define SSH_DISCONNECT_RESERVED                             4
#define SSH_DISCONNECT_MAC_ERROR                            5
#define SSH_DISCONNECT_COMPRESSION_ERROR                    6
#define SSH_DISCONNECT_SERVICE_NOT_AVAILABLE                7
#define SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED       8
#define SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE              9
#define SSH_DISCONNECT_CONNECTION_LOST                     10
#define SSH_DISCONNECT_BY_APPLICATION                      11
#define SSH_DISCONNECT_TOO_MANY_CONNECTIONS                12
#define SSH_DISCONNECT_AUTH_CANCELLED_BY_USER              13
#define SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE      14
#define SSH_DISCONNECT_ILLEGAL_USER_NAME                   15


/*
==================
Reason Codes
==================
*/
#define SSH_OPEN_ADMINISTRATIVELY_PROHIBITED                1
#define SSH_OPEN_CONNECT_FAILED                             2
#define SSH_OPEN_UNKNOWN_CHANNEL_TYPE                       3
#define SSH_OPEN_RESOURCE_SHORTAGE                          4


/*
==================
Operational codes
Mnemonic 			Opcode 		Description
==================
*/
/*
#define TTY_OP_END		0     // Indicates end of options.
#define VINTR 			1     // Interrupt character; 255 if none.  Similarly
                			  // for the other characters.  Not all of these
                			  // characters are supported on all systems.
#define VQUIT 			2     // The quit character (sends SIGQUIT signal on
                			  // POSIX systems).
#define VERASE 			3     // Erase the character to left of the cursor.
#define VKILL 	        4     // Kill the current input line.
#define VEOF 	 		5     // End-of-file character (sends EOF from the
                			  // terminal).
#define VEOL 			6     // End-of-line character in addition to
                              // carriage return and/or linefeed.
#define VEOL2 			7     // Additional end-of-line character.
#define VSTART 			8     // Continues paused output (normally
                			  // control-Q).
#define VSTOP 			9     // Pauses output (normally control-S).
#define VSUSP 			10    // Suspends the current program.
#define VDSUSP 			11    // Another suspend character.
#define VREPRINT 		12    // Reprints the current input line.
#define VWERASE 		13    // Erases a word left of cursor.
#define VLNEXT 			14    // Enter the next character typed literally,
                		      // even if it is a special character
#define VFLUSH	 		15    // Character to flush output.
#define VSWTCH 			16    // Switch to a different shell layer.
#define VSTA 			17    // Prints system status line (load, command,
                			  // pid, etc).
#define VDISCARD 		18    // Toggles the flushing of terminal output.
#define IGNPAR 			30    // The ignore parity flag.  The parameter
                			  // SHOULD be 0 if this flag is FALSE,
                			  // and 1 if it is TRUE.
#define PARMRK 			31    // Mark parity and framing errors.
#define INPCK 			32    // Enable checking of parity errors.
#define ISTRIP 			33    // Strip 8th bit off characters.
#define INLCR 			34    // Map NL into CR on input.
#define IGNCR 			35    // Ignore CR on input.
#define ICRNL 			36    // Map CR to NL on input.
#define IUCLC 			37    // Translate uppercase characters to
                			  // lowercase.
#define IXON 			38    // Enable output flow control.
#define IXANY 			39    // Any char will restart after stop.
#define IXOFF 			40    // Enable input flow control.
#define IMAXBEL 		41    // Ring bell on input queue full.
#define ISIG 			50    // Enable signals INTR, QUIT, [D]SUSP.
#define ICANON 			51    // Canonicalize input lines.
#define XCASE 			52    // Enable input and output of uppercase
                  			  // characters by preceding their lowercase
                  			  // equivalents with \.
#define ECHO 			53    // Enable echoing.
#define ECHOE 			54    // Visually erase chars.
#define ECHOK 			55    // Kill character discards current line.
#define ECHONL 			56    // Echo NL even if ECHO is off.
#define NOFLSH 			57    // Don't flush after interrupt.
#define TOSTOP 			58    // Stop background jobs from output.
#define IEXTEN 			59    // Enable extensions.
#define ECHOCTL 		60    // Echo control characters as ^(Char).
#define ECHOKE 			61    // Visual erase for line kill.
#define PENDIN 			62    // Retype pending input.
#define OPOST 			70    // Enable output processing.
#define OLCUC 			71    // Convert lowercase to uppercase.
#define ONLCR 			72    // Map NL to CR-NL.
#define OCRNL 			73	  // Translate carriage return to newline
                			  // (output).
#define ONOCR 			74	  // Translate newline to carriage
                			  // return-newline (output).
#define ONLRET 			75	  // Newline performs a carriage return
                			  // (output).
#define CS7 			90 	  // 7 bit mode.
#define CS8 			91    // 8 bit mode.
#define PARENB 			92	  // Parity enable.
#define PARODD 			93	  // Odd parity, else even.

#define TTY_OP_ISPEED 	128   // Specifies the input baud rate in
                 			  // bits per second.
#define TTY_OP_OSPEED 	129   // Specifies the output baud rate in
                 			  // bits per second.
*/