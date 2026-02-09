MON_SRC=mon_test.c

MON_PROG_OUT=mon_prog_test
UNMON_PROG_OUT=unmon_prog_test
MON_EUID_OUT=mon_euid_test
UNMON_EUID_OUT=unmon_euid_test

CFLAGS=-Wall -Wextra

all:
	$(CC) $(CFLAGS) -o $(MON_PROG_OUT) $(MON_SRC)
	$(CC) $(CFLAGS) -o $(UNMON_PROG_OUT) $(MON_SRC)
	$(CC) $(CFLAGS) -o $(MON_EUID_OUT) $(MON_SRC)
	$(CC) $(CFLAGS) -o $(UNMON_EUID_OUT) $(MON_SRC)

clean:
	rm -f $(MON_PROG_OUT) $(UNMON_PROG_OUT) $(MON_EUID_OUT) $(UNMON_EUID_OUT)