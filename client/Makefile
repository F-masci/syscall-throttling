CLIENT_SRC=client.c
PAUSE_SRC=pause.c

CLIENT_OUT=client
PAUSE_OUT=pause

CFLAGS=-Wall -Wextra

all:
	$(CC) $(CFLAGS) -o $(CLIENT_OUT) $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $(PAUSE_OUT) $(PAUSE_SRC)

clean:
	rm -f $(CLIENT_OUT) $(PAUSE_OUT)