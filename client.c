//client 
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>
#include <curses.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#define PORT 1234
#define SERVER "127.0.0.1"
#define CACERT "./private/ca.crt"
#define MYCERTF "./certs/client.crt"
#define MYKEYF "./private/client.key"
#define MSGLENGTH 1024

void sendProc(void *arg);
void recvProc(void * arg);

//send messages
void sendProc(void * arg)
{
		SSL *ssl = (SSL *)arg ;
		
		char sendBuffer[1024] = { 0 };
		memset(sendBuffer, 0 , 1024);
		while(1)
		{
				printf("please input the message you want to send :");
				fgets(sendBuffer, sizeof(sendBuffer), stdin);

				if (strlen(sendBuffer) == sizeof(sendBuffer) - 1 && sendBuffer[sizeof(sendBuffer) - 2] != '\n')
				{
					scanf("%*[^\n]");
					scanf("%*c");
				}
				sendBuffer[strlen(sendBuffer) - 1] = '\0';
				if(!strcmp(sendBuffer,"quit") || !strcmp(sendBuffer,"q"))
				{
					printf("the communication is end ");
					break;
				}
				if( SSL_write (ssl, (char *)&sendBuffer, strlen (sendBuffer)) == -1 )
				{
						printf("send failed \n");
						break;
				}
				memset(sendBuffer, 0, sizeof(sendBuffer));
				sleep(1);				
		}
		
}

//recv messages
void recvProc(void *arg)
{
		SSL *ssl = (SSL *)arg;
		char recvBuffer[1024] = { 0 };
	
		while (1)
		{
				memset(recvBuffer, 0x00, sizeof(recvBuffer));
				int ret = SSL_read (ssl, recvBuffer, sizeof (recvBuffer) );
				if( ret > 0)
				{
						recvBuffer[ret] = '\0';
						printf("\nMessage from this server : %s\n", recvBuffer);
						if(!strcmp(recvBuffer , "quit") || !strcmp(recvBuffer , "q"))
						{
							perror(" the client quit .");
						}
				}				
				else
				{
						perror(" The server has been disconnecting !\n");
						break;
				}
				sleep(2);
		}
}


int main ()
{
		struct sockaddr_in sin;
		
		SSL *ssl;
		SSL_METHOD *meth;
		SSL_CTX *ctx;
		pthread_t id1,id2;
		
		int i;
		
		/* 载入所有 SSL 算法 */
		OpenSSL_add_ssl_algorithms ();
		/* 载入所有 SSL 错误消息 */
		SSL_load_error_strings ();
		/* 创建本次会话所用协议 调用SSLv3 */
		meth = (SSL_METHOD *) SSLv23_client_method ();
		/* 创建SSL会话环境 */
		ctx = SSL_CTX_new (meth);
		if (NULL == ctx)
				exit (1);
		/* 设置证书验证 SSL_VERIFY_PEER 进行客户端服务器双向验证*/
		SSL_CTX_set_verify (ctx, SSL_VERIFY_PEER, NULL);
		/* 加载CA证书 */
		SSL_CTX_load_verify_locations (ctx, CACERT, NULL);
		/* 加载客户端证书 client.crt，里面含有客户端公钥，用来发送给服务器*/
		if (0 == SSL_CTX_use_certificate_file (ctx, MYCERTF, SSL_FILETYPE_PEM))
		{
				ERR_print_errors_fp (stderr);
				exit (1);
		}
		/* 加载客户端私钥 client.key */
		if (0 == SSL_CTX_use_PrivateKey_file (ctx, MYKEYF, SSL_FILETYPE_PEM))
		{
				ERR_print_errors_fp (stderr);
				exit (1);
		}
		/* 检查客户端证书与私钥是否匹配 */
		if (!SSL_CTX_check_private_key (ctx))
		{
				printf ("Private key does not match the certificate public key\n");
				exit (1);
		}
		
		SSL_CTX_set_cipher_list (ctx, "RC4-MD5");
		SSL_CTX_set_mode (ctx, SSL_MODE_AUTO_RETRY);
		int sock;
		printf ("Begin tcp socket...\n");
		sock = socket (AF_INET, SOCK_STREAM, 0);
		if (sock == -1)
		{
				printf ("SOCKET error. \n");
		}
		
		memset (&sin, '\0', sizeof (sin));
		
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = inet_addr (SERVER); /* Server IP */
		sin.sin_port = htons (PORT); /* Server Port number */
		int icnn = connect (sock, (struct sockaddr *) &sin, sizeof (sin));
				
		if (icnn == -1)
		{
				printf ("can not connect to server,%s\n", strerror (errno));
				exit (1);
		}
		
		ssl = SSL_new (ctx);
		if (NULL == ssl)
				exit (1);
		if (0 >= SSL_set_fd (ssl, sock))
		{
				printf ("Attach to Line fail!\n");
				exit (1);
		}
		/* SSL的握手 */
		int k = SSL_connect (ssl);
		if (0 == k)
		{
				printf ("%d\n", k);
				printf ("SSL connect fail!\n");
				exit (1);
		}
		printf ("connect to server\n");
		
		pthread_create(&id1,NULL,(void *)sendProc,(SSL *)ssl);
		pthread_create(&id2,NULL,(void *)recvProc,(SSL *)ssl);
		pthread_join(id1,NULL);
		pthread_join(id2,NULL);

		SSL_shutdown (ssl);
		SSL_free (ssl);
		SSL_CTX_free (ctx);
		close (sock);
		return 0;
}
