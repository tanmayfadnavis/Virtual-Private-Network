INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	g++ -I$(INC) -L$(LIB) -o MiniVPN MiniVPN.c -lssl -lcrypto -ldl

clean:
	rm -rf *~ MiniVPN
