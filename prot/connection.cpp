#include "connection.h"
#include "session.h"

#include <pthread.h>


/*
==================
StdinThread

Background thread reading stdin-input and storing it
in 'g_input'. The background thread quits when 't_continue'
is set to false.
==================
*/
pthread_mutex_t inlock;
string g_input;
bool t_continue = true;

void StdinNoncanonical(struct termios &orgopt) {
	struct termios new_opts;

	tcgetattr(STDIN_FILENO, &orgopt);
	memcpy(&new_opts, &orgopt, sizeof(new_opts));

	new_opts.c_lflag &= ~(ECHO);
	new_opts.c_lflag &= ~(ICANON);
	new_opts.c_cc[VMIN] = 0;
	new_opts.c_cc[VTIME] = 0;
	tcsetattr(STDIN_FILENO, TCSANOW, &new_opts);
}

void StdinCanonical(struct termios &orgopt) {
	tcsetattr(STDIN_FILENO, TCSANOW, &orgopt);
}

void* StdinThread(void*) {
	struct termios orgopts;
	int c=0, res=0;

	StdinNoncanonical(orgopts);

	while (t_continue) {
		while ((c = getchar()) > 0) {
			pthread_mutex_lock(&inlock);
			g_input += c;
			pthread_mutex_unlock(&inlock);
		}
		
		usleep(10000);
	}

  	StdinCanonical(orgopts);

  	return NULL;
}


/*
==================
Connection::Connection
==================
*/
Connection::Connection(Socket *s) {
	socket = s;
	quit = false;

	channel = new Channel(CH_CLI, 0, "session", s);
}

/*
==================
Connection::~Connection
==================
*/
Connection::~Connection() {
	if (channel) {
		delete channel;
	}
}

/*
==================
Connection::MainLoop

Return values:
	-1   on error
	 0   on success
==================
*/
int Connection::MainLoop() {
	pthread_t inputThread;

	if (pthread_mutex_init(&inlock, NULL)) {
		Error("Failed to create mutex", errno);
		return -1;
	}

	if (pthread_create(&inputThread, NULL, &StdinThread, NULL)) {
		Error("Failed to create stdin-thread", errno);
		return -1;
	}

	if (!channel->Init()) {
		return -1;
	}

	while (!quit) {
		while (socket->HasData())  {
			DispatchPacket();
		}
			
		HandleInput();

		usleep(10000);
	}

	socket->Disconnect();

	t_continue = false;
	pthread_join(inputThread, NULL);
	pthread_mutex_destroy(&inlock);

	return 0;
}

/*
==================
Connection::DispatchPacket
==================
*/
void Connection::DispatchPacket() {
	ubyte *data;
	uint32 len;

	data = socket->Read();
	len = socket->LastSize();

	if (!len || !data) {
		printf("Socket tricked me - it had no data!\n");
		return;
	}

	Packet p(data, len);

	switch (p.type) {
		case SSH_MSG_REQUEST_SUCCESS:
		case SSH_MSG_REQUEST_FAILURE:
		case SSH_MSG_CHANNEL_OPEN:
		case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
		case SSH_MSG_CHANNEL_OPEN_FAILURE:
		case SSH_MSG_CHANNEL_WINDOW_ADJUST:
		case SSH_MSG_CHANNEL_CLOSE:
		case SSH_MSG_CHANNEL_REQUEST:
		case SSH_MSG_CHANNEL_SUCCESS:
		case SSH_MSG_CHANNEL_FAILURE:
		case SSH_MSG_CHANNEL_DATA:
		case SSH_MSG_CHANNEL_EXTENDED_DATA:
		case SSH_MSG_CHANNEL_EOF:
			channel->HandleMessage(data, len);
			break;

		case SSH_MSG_GLOBAL_REQUEST:
			/* TODO */

		default:
			printf("[Conn] Unidentified packet:\n");
			Session::GetSingleton()->DeterminePacket(data,len);
			break;
	}
}

/*
==================
Connection::HandleInput
==================
*/
void Connection::HandleInput() {
	pthread_mutex_lock(&inlock);

	channel->SendInput(g_input);
	g_input = "";

	pthread_mutex_unlock(&inlock);
}