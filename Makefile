all:client.c server.c
	gcc -Wall -o client client.c -I/usr/local/ssl/include /usr/local/ssl/lib/libssl.a /usr/local/ssl/lib/libcrypto.a -ldl -lpthread
	gcc -Wall -o server server.c -I/usr/local/ssl/include /usr/local/ssl/lib/libssl.a /usr/local/ssl/lib/libcrypto.a -ldl -lpthread
clean::
	rm -f client server
