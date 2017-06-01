#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <errno.h>
#include <memory.h>
#include <unistd.h>
#include <termios.h>

#include <arpa/inet.h>
#include <fcntl.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netdb.h>

#include <linux/if_tun.h>
#include <getopt.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>   	/* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// toggle controlling whether to show debug information
#define DEBUG 0

#define PERROR(x) { perror(x); exit(1); }
#define ERROR(x, args ...) { fprintf(stderr,"ERROR:" x, ## args); exit(1); }

// define length of hmac
#define HMAC_LEN 16
// buffer size of one packet
#define BUFF_SIZE 51200
#define KEY_IV_SIZE 16
#define FAIL    -1

#define CHK_NULL(x) if ((x)==NULL) { printf("NULL!!\n"); exit(1); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

/* Make these what you want for cert & key files */
static char SER_CERTF[] = "server.crt";
static char SER_KEYF[] = "server.key";
static char CACERT[] = "ca.crt";

// common names
//static char SER_CERT_CN[] = "server.minivpn.syr.edu";
char SER_CERT_CN[40];

unsigned char KEY[KEY_IV_SIZE], IV[KEY_IV_SIZE];

void generateHash(char *message,unsigned char *md_value);
int genRandom();
void getHash(char * msg, int len, char * digt);
// generate random key
void genKey(unsigned char* key)
{
   int i;
   srand(time(NULL));
   for (i=0; i<KEY_IV_SIZE; i++)
   key[i] = 65 + (genRandom()%26);
}

int genRandom()
{

	unsigned int seed;
	FILE* urandom = fopen("/dev/urandom","r");
	fread(&seed,sizeof(int),1,urandom);
	fclose(urandom);
	srand(seed);

	return rand();

}

// generate random iv
void genIV(unsigned char* iv) {
   int i;
   srand(time(NULL));
   for (i=0; i<KEY_IV_SIZE; i++)
   iv[i] = 48 + (genRandom()%10);
}
void showKeyOrIV(unsigned char* chrs) {
    int i;
    for (i=0; i<KEY_IV_SIZE; i++)
   	 printf("%c", chrs[i]);
}

// append HMAC to the end of buff
void appendIV(char * payload,unsigned char * iv, int * l)
{



   char digt[HMAC_LEN], buff[BUFF_SIZE];
   int i, len = *l;
   if (DEBUG) {
	for(i = 0; i < KEY_IV_SIZE; i++) 
	printf("%02x", iv[i]);
	}
   //strcat(buff,iv);
   memcpy(buff, payload, len);

   for (i=0;i< KEY_IV_SIZE;i++)
  *(payload + len + i) = iv[i];
len += KEY_IV_SIZE;

   memcpy(buff, payload, len);
   getHash(buff, len, digt);
   for (i=0;i<HMAC_LEN;i++)
  *(payload + len + i) = digt[i];
   len += HMAC_LEN;


   if (DEBUG) {
  printf("\nappend iv HMAC: ");
  for(i = len-HMAC_LEN; i < len; i++) printf("%02x", *(payload+i));
  printf("\n");
   }
   *l = len;
}


int checkIV(char * payload, unsigned char *iv,int * l)
{


   char digt1[HMAC_LEN], digt2[HMAC_LEN], buff[BUFF_SIZE];    

   int i, len = *l;

   len -= KEY_IV_SIZE;
   if (len <=0) return 1;
   memcpy(iv, payload + len, KEY_IV_SIZE);
   if (DEBUG) {
	for(i = 0; i < KEY_IV_SIZE; i++) 
	printf("%02x", iv[i]);
	}


   len -= HMAC_LEN;
   memcpy(digt1, payload + len, HMAC_LEN);
   memcpy(buff, payload, len);
   getHash(buff, len, digt2);
   if (DEBUG) {
  printf("checking HMAC: ");
  for(i = 0; i < HMAC_LEN; i++) printf("%02x", digt1[i]);
  printf(" / ");
  for(i = 0; i < HMAC_LEN; i++) printf("%02x", digt2[i]);
  printf("\n");
   }
   *l = len;


   return strncmp(digt1, digt2, HMAC_LEN);
}

// get hash value of one message
void getHash(char * msg, int len, char * digt) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    
    size_t i;
    unsigned int md_len;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    char hashname[] = "md5";    
    OpenSSL_add_all_digests();
    md = EVP_get_digestbyname(hashname);
    if(!md) {
   	 printf("Unknown message digest %s\n", hashname);
   	 exit(1);
    }
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, msg, len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_destroy(mdctx);
    // md_len == HMAC_LEN == 16 at this stage
    memcpy(digt, md_value, HMAC_LEN);
}


int checkHMAC(char * payload, int * l) {
    char digt1[HMAC_LEN], digt2[HMAC_LEN], buff[BUFF_SIZE];     
    int i, len = *l;
    
    len -= HMAC_LEN;
    if (len <=0) return 1;
    memcpy(digt1, payload + len, HMAC_LEN);
    memcpy(buff, payload, len);
    getHash(buff, len, digt2);
    if (DEBUG) {
   	 printf("checking HMAC: ");
   	 for(i = 0; i < HMAC_LEN; i++) printf("%02x", digt1[i]);
   	 printf(" / ");
   	 for(i = 0; i < HMAC_LEN; i++) printf("%02x", digt2[i]);
   	 printf("\n");
    }
    *l = len;
    return strncmp(digt1, digt2, HMAC_LEN);
}


void appendHMAC(char * payload, int * l) {
    char digt[HMAC_LEN], buff[BUFF_SIZE];
    int i, len = *l;
    memcpy(buff, payload, len);
    getHash(buff, len, digt);
    for (i=0;i<HMAC_LEN;i++)
   	 *(payload + len + i) = digt[i];
    len += HMAC_LEN;
    if (DEBUG) {
   	 printf("\nappend HMAC: ");
   	 for(i = len-HMAC_LEN; i < len; i++) printf("%02x", *(payload+i));
   	 printf("\n");
    }
    *l = len;
}


int do_crypt(unsigned char *key, unsigned char * iv, char * packet, int *l, int do_encrypt) {
    unsigned char outbuf[BUFF_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen = *l, outlen, tmplen, i;
    unsigned char input[BUFF_SIZE];
    // convert text
    memcpy(input, packet, inlen);
    if (DEBUG) {
   	 printf("\n(before crypted) payload: ");
   	 for(i = 0; i < inlen; i++) printf("%02x", *(input+i));
   	 printf("\n");
    }

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv, do_encrypt);

    if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, input, inlen)) {
   	 /* Error */
   	 EVP_CIPHER_CTX_cleanup(&ctx);
   	 return 0;
    }
    if(!EVP_CipherFinal_ex(&ctx, outbuf + outlen, &tmplen)) {
   	 /* Error */
   	 EVP_CIPHER_CTX_cleanup(&ctx);
   	 return 0;
    }
    outlen += tmplen;
    if (DEBUG) {
   	 printf("\n(crypted) payload: ");
   	 for(i = 0; i < outlen; i++) printf("%02x", *(outbuf+i));
   	 printf("\n");
    }
    memcpy(packet, outbuf, outlen);    // update packet
    *l = outlen;
    EVP_CIPHER_CTX_cleanup(&ctx);
    return 1;    // return as successful
}


void usage() {
    fprintf(stderr, "Usage: MiniVPN [-s port|-c targetip:port]\n");
    exit(0);
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);             /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);             /* free the malloc'ed string */
        X509_free(cert);          /* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	/* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile  */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}


int keyXchange_setupCTX(char* certf, char* keyf, const SSL_METHOD* meth, SSL_CTX** ctx) {
    
    OpenSSL_add_all_algorithms();		/* load & register all cryptos, etc. */
    SSL_load_error_strings();			/* load all error messages */
   
    SSLeay_add_ssl_algorithms();
	(*ctx) = SSL_CTX_new(meth);
	
	if (!(*ctx)) {
		printf("CTX is null!");
		ERR_print_errors_fp(stderr);
		exit(2);
    }
    
	
	SSL_CTX_set_verify((*ctx), SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations((*ctx), CACERT, NULL);
    
	LoadCertificates(*ctx, certf, keyf);
	
	return 1;
}


int keyXchange_chk_peer_cert(SSL* ssl, char* commonName) {
    X509* peer_cert;
    char* str;
    char peer_CN[256];
    printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
    
    peer_cert = SSL_get_peer_certificate (ssl);
    
    if (peer_cert != NULL) {  
   	 X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert),  NID_commonName, peer_CN, 256);
   	 
	 if(strcasecmp(peer_CN, commonName)) {
   		 printf("peer common name: %s, local request: %s\n", peer_CN, commonName);
   		 PERROR("Common name doesn't match host name\n");
   	 }
   	 else {
   		 printf("Common Names are the same: %s \n", commonName);
		 X509_free (peer_cert);
		 return 1;
   	 }

   	 X509_free (peer_cert);
    } else
   	 PERROR ("Peer does not have certificate.\n");
   return 0;
}


void keyXchange_sendKey(SSL* ssl, unsigned char* key) {
    int i;
    char buf[4096];
    buf[0] = 'k';    // mark as key
    for (i=0; i<KEY_IV_SIZE; i++)
   	 buf[i+1] = key[i];
    i = SSL_write(ssl, buf, KEY_IV_SIZE+1);
    CHK_SSL(i);
    // read echo
    i = SSL_read(ssl, buf, sizeof(buf) - 1);
    CHK_SSL(i);
    buf[i] = '\0';
    if (buf[0]=='l') {
   	 printf("Key confirmed by remote peer: ");
   	 showKeyOrIV(key);
   	 printf("\n");
    }
    else
   	 PERROR("Key exchange fail!\n");
}


void keyXchange_sendIV(SSL* ssl, unsigned char* iv) {
    int i;
    char buf[4096];
    buf[0] = 'i';    // mark as iv
    for (i=0; i<KEY_IV_SIZE; i++)
   	 buf[i+1] = iv[i];
    i = SSL_write(ssl, buf, KEY_IV_SIZE+1);
    CHK_SSL(i);
    
    i = SSL_read(ssl, buf, sizeof(buf) - 1);
    CHK_SSL(i);
    buf[i] = '\0';
    if (buf[0]=='j') {
   	 printf("IV confirmed by remote peer: ");
   	 showKeyOrIV(iv);
   	 printf("\n");
    }
    else
   	 PERROR("IV exchange fail!\n");
}

int keyXchange_receiveKey(SSL* ssl, char* buf, size_t len, unsigned char* key) {
    int i;
    if (len!=KEY_IV_SIZE+1 || buf[0]!='k') return 0;
    for (i=1; i<len; i++)
   	 key[i-1] = buf[i];
    i = SSL_write(ssl, "l", 1);
    CHK_SSL(i);
    printf("KEY received: ");
    showKeyOrIV(key);
    printf("\n");
    return 1;
}

int checkHash(char *enteredPwd, char *salt, char *pwdHash)
{
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int i=0;
	int flag = 1;
	char *genHash = (char *)malloc(sizeof(char)*64);
	memset(genHash, '\0', sizeof(genHash));
	char *temp = (char *)malloc(sizeof(char));
	printf("%s\n",salt);
	printf("%s\n",enteredPwd);
	strcat(enteredPwd,salt);
	generateHash(enteredPwd,md_value);

	for(i =0;i<32;i++)
	{
		sprintf(temp,"%x",md_value[i]);
		strcat(genHash,temp);
	}

	printf("%s\n",genHash);
	printf("%s\n",pwdHash);
	for(i = 0;i <64;i++)
	{
	if(pwdHash[i]!=genHash[i])
		{
			flag = 0;
			break;
		}

	}

	if(flag==0){
		printf("password not matched\n");
		return 0;
	}	else{
		printf("password match\n");
		return 1;
	}
}


int ReadFromFile(char *enteredUName, char *enteredPwd, FILE *inputFilePtr) {
  char readLine[100];
  char *userName;
  char *salt = (char *)malloc(sizeof(char) * 2); 
  char *pwdHash = (char *)malloc(sizeof(char) * 64);
  int count = 0;
  
  if(inputFilePtr == NULL){
    printf("\nError opening the file file1.txt\n");
    return 0;
  }

  else {
    while(fgets(readLine,100,inputFilePtr)!=NULL) {
      if(strcmp(readLine,"\n")) {
        
        userName = strtok(readLine,",");
        salt = strtok(NULL,",");
        pwdHash = strtok(NULL,","); 

        if(strcmp(userName,enteredUName)==0){
          return checkHash(enteredPwd,salt,pwdHash);
          break;
        }
      }
    }
  }
}

int keyXchange_receiveIV(SSL* ssl, char* buf, size_t len, unsigned char* iv) {
    int i;
    if (len!=KEY_IV_SIZE+1 || buf[0]!='i') return 0;
    for (i=1; i<len; i++)
   	 iv[i-1] = buf[i];
    i = SSL_write(ssl, "j", 1);
    CHK_SSL(i);
    printf("IV received: ");
    showKeyOrIV(iv);
    printf("\n");
    return 1;
}

void keyXchange_server(int listen_port, unsigned char* key, unsigned char* iv, int pipefd, int pid) {
    int err, listen_sd, sd, i, res = 0;
    int _keyReady = 0, _ivReady = 0;
    struct sockaddr_in sa_serv;
        
	int flag=0;
    FILE *inputFilePtr;
	
	printf("\nServer is up and running\n");
	
	inputFilePtr = fopen("file1.txt", "r");
	SSL_CTX* ctx;
	keyXchange_setupCTX(SER_CERTF, SER_KEYF, SSLv23_server_method(), &ctx);
    listen_sd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(listen_sd, "socket");

    memset(&sa_serv, '\0', sizeof(sa_serv));
    sa_serv.sin_family = AF_INET;
    sa_serv.sin_addr.s_addr = htonl(INADDR_ANY);
    sa_serv.sin_port = htons(listen_port);      	/* Server Port number */

    err = bind(listen_sd, (struct sockaddr*) &sa_serv, sizeof (sa_serv));
    CHK_ERR(err, "bind");
    err = listen (listen_sd, 10);
    CHK_ERR(err, "listen");
    
	    
	while(true){
		struct sockaddr_in sa_cli;
		unsigned int client_len = sizeof(sa_cli);

		SSL* ssl;
		char buf[1024];
		char uname[40]; char passwd[20];
		
		sd = accept(listen_sd, (struct sockaddr*) &sa_cli, &client_len);
		CHK_ERR(sd, "accept");
		    	
		ssl = SSL_new(ctx);         					/* get new SSL state with context */
		SSL_set_fd(ssl, sd);
		
		err = SSL_accept(ssl);
		CHK_SSL(err);

		SSL_read(ssl,uname, 40);
		SSL_read(ssl,passwd, 20);

		res=ReadFromFile(uname,passwd,inputFilePtr);

		if(res == 0){
			printf("Login Failed\n");
			SSL_write(ssl, "Login failed", 100);
		} 
	
		if(res == 1) {
			printf("Login Success\n");
			SSL_write(ssl, "Success Login", 100);
			flag=1;
		}
	
		
		
		if(flag)
			printf("Connection from %s:%i\n", inet_ntoa(sa_cli.sin_addr), ntohs(sa_cli.sin_port));
		else
			printf("Connection Attempt from %s:%i failed\n", inet_ntoa(sa_cli.sin_addr), ntohs(sa_cli.sin_port));
		
		if(flag){
			while (1) {
				_keyReady = 0;
				_ivReady = 0;
				
				while (!_keyReady || !_ivReady) {
					err = SSL_read(ssl, buf, sizeof(buf) - 1);
					CHK_SSL(err);
					buf[err] = '\0';
					_keyReady = _keyReady || keyXchange_receiveKey(ssl, buf, err, KEY);
					_ivReady = _ivReady || keyXchange_receiveIV(ssl, buf, err, IV);
				}
   	 // notify the child process
				buf[0] = 'k';
   	 // send key and iv to children
				for (i=0; i<KEY_IV_SIZE; i++) {
					buf[i+1] = KEY[i];
					buf[i+KEY_IV_SIZE+1] = IV[i];
				}
				
				buf[KEY_IV_SIZE*2+1] = '\0';
   	 // check if this is a disconnect signal
				_keyReady = 0;
				_ivReady = 0;
   	 
				for (i=0; i<KEY_IV_SIZE; i++) {
					_keyReady = _keyReady || (int)KEY[i];
					_ivReady = _ivReady || (int)IV[i];
				}
				
				memset(KEY,'\0',16);                                
				memset(IV,'\0',16);
				
				if (!_keyReady && !_ivReady) {
					printf("Disconnect signal from client received!\n");
					kill(pid, SIGTERM);
					wait();
					break;
				}
				
				
				write(pipefd, buf, KEY_IV_SIZE*2+2);
			}
		}	
		close(sd);
		SSL_free (ssl);
	}
	SSL_CTX_free (ctx);
    fclose(inputFilePtr);
}


void generateHash(char *message,unsigned char *md_value)
{
	EVP_MD_CTX *mdctx;
	const EVP_MD *md; 
	int i;
	unsigned int md_len;
	char *hashAlg = "sha256";
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname(hashAlg);

	 if(!md) {
		printf("Unknown message digest %s\n", hashAlg);
		exit(1);
	 }

	 mdctx = EVP_MD_CTX_create();
	 EVP_DigestInit_ex(mdctx, md, NULL);
	 EVP_DigestUpdate(mdctx, message, strlen(message));
	 EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	 EVP_MD_CTX_destroy(mdctx);	

	printf("Digest is: ");
	 for(i = 0; i < md_len; i++) printf("%02x", md_value[i]);
	 printf("\n"); 

}

int getch(void) {
	struct termios oldattr, newattr;
	int ch;
	tcgetattr( STDIN_FILENO, &oldattr );
	newattr = oldattr;
	newattr.c_lflag &= ~( ICANON | ECHO );
	tcsetattr( STDIN_FILENO, TCSANOW, &newattr );
	ch = getchar();
	tcsetattr( STDIN_FILENO, TCSANOW, &oldattr );
	return ch;
}


int keyXchange_client(char* ip, int remote_port, char* commonName, unsigned char* key, unsigned char* iv, int pipefd, int pid) {
    int readLen,err, sd, i,loggedin = 0;
    struct sockaddr_in sa;
    char buf[1024];
    char uname[40], pwd[20];
    SSL *ssl;

    const SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL_library_init();

    OpenSSL_add_all_algorithms();   /* Load cryptos, et.al. */
    SSL_load_error_strings();     /* Bring in and register error messages */
    method = SSLv23_client_method();   /* Create new client-method instance */
    ctx = SSL_CTX_new(method);      /* Create new context */
	
    if ( ctx == NULL )
    {   
		ERR_print_errors_fp(stderr);
        abort();
    }

    sd = socket (AF_INET, SOCK_STREAM, 0);
    CHK_ERR(sd, "socket");
    memset (&sa, '\0', sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(ip);   /* Server IP */
    sa.sin_port = htons(remote_port);       /* Server Port number */

    err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));
    CHK_ERR(err, "connect");

    ssl = SSL_new(ctx);           /* create new SSL connection state */
    CHK_NULL(ssl);
  
    SSL_set_fd(ssl, sd);
    SSL_connect(ssl);
	if(DEBUG) ShowCerts(ssl);

    i=keyXchange_chk_peer_cert(ssl, commonName);
	
	if(i==0){
	printf("Unauthenticated server. Exiting");
	exit(1);
	}
    
	printf("Please enter your username: " );
    scanf("%s", uname);
    printf("\nPlease enter your password: ");
	
	i=0;
	getch();
	
	while ((pwd[i] = getch()) != '\n' && pwd[i] != '\r' && i < 19){
		i++;
	}
	pwd[i] = '\0';
    SSL_write(ssl, uname, 40);
	SSL_write(ssl, pwd, 20);
    memset(buf, '\0', 1024);
	memset(uname, '\0', 40);
	memset(pwd, '\0', 20);
	
    readLen = SSL_read(ssl, buf, 100);
	
    printf("\n%s", buf);
	
    if(buf[0] == 'S'){
		loggedin=1;
    } 
    else {
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		close(sd);
	}

    while (1) {
   	 printf("\nPlease input some instructions ('q' for abort, 'k' for changing key, or 'c' for continue):\n");
   	 scanf("%s", buf);
   	 if (strlen(buf) == 1) {
   		 if (buf[0]=='q') {    // abort
   			 kill(pid, SIGTERM);
   			 wait();
   			 break;
   		 }
   		 else if (buf[0]=='k') {
   				 genKey(KEY);
   			 	 genIV(IV);
   		 }
   	 }
   	 else if (strlen(buf) > 0 && buf[0]!='c') {
   		 printf("Invalid input. Try again.\n");
   		 continue;
   	 }

   	 // exchange key and iv
   	 keyXchange_sendKey(ssl, key);
   	 keyXchange_sendIV(ssl, iv);
	 

   	 // notify the child process
   	 buf[0] = 'k';
   	 // send key and iv to children
   	 for (i=0; i<KEY_IV_SIZE; i++) {
   		 buf[i+1] = KEY[i];
   		 buf[i+KEY_IV_SIZE+1] = IV[i];
   	 }
   	 buf[KEY_IV_SIZE*2+1] = '\0';
   	 write(pipefd, buf, KEY_IV_SIZE*2+2);
    }
    // send signal to notify server to disconnect by sending NULL key & IV
    for (i=0; i<KEY_IV_SIZE; i++) {
   	 KEY[i] = 0;
   	 IV[i] = 0;
    }
    keyXchange_sendKey(ssl, key);
    keyXchange_sendIV(ssl, iv);

    SSL_shutdown(ssl);  /* send SSL/TLS close_notify */
    close(sd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}


void startVPN(int MODE, int listen_port, char *ip, int remote_port, int pipefd) {
    struct sockaddr_in sin, sout;
    struct ifreq ifr;
    socklen_t soutlen;
    int fd, s, l, i, keyXchange_count = 0;
    fd_set fdset;
    char buf[BUFF_SIZE], digt[HMAC_LEN];
	// open tunnel
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) PERROR("open");

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN;    // always use tun here
    strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) PERROR("ioctl");
        
	printf("\nAllocated interface %s. Configure and use it\n", ifr.ifr_name);

    s = socket(PF_INET, SOCK_DGRAM, 0);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(listen_port);

    if (bind(s,(struct sockaddr *)&sin, sizeof(sin)) < 0) PERROR("bind");
    soutlen = sizeof(sout);
    if (MODE == 2) { // for client
   	 sout.sin_family = AF_INET;
   	 sout.sin_port = htons(remote_port);
   	 inet_aton(ip, &sout.sin_addr);
    }

    while (1) {
	l = read(pipefd, buf, sizeof(buf));

   	 if (l > 0) {
	 // if we get some command from parent process
   		 if (l == 1 && buf[0]=='q') {
   			 	
			printf("before exit\n\n");
   			 _exit(0);
   		 }
   		 else if (buf[0]=='k') {
   			 for (i=0; i<KEY_IV_SIZE; i++) {
   				 KEY[i] = buf[i+1];
   				 IV[i] = buf[i+KEY_IV_SIZE+1];
   			 }
   		 }
   		 printf("Child process >> KEY: ");
   		 showKeyOrIV(KEY);
   		 printf("  IV: ");
   		 showKeyOrIV(IV);
   		 keyXchange_count++;    // now we can start
   			 printf("\n");
   	 }
	 FD_ZERO(&fdset);
   	 FD_SET(fd, &fdset);
   	 FD_SET(s, &fdset);
   	 if (select(fd+s+1, &fdset,NULL,NULL,NULL) < 0) PERROR("select");
   	 if (FD_ISSET(fd, &fdset)) {
		 if (DEBUG) printf("\n SENT >> ");
   		 l = read(fd, buf, BUFF_SIZE);
   		 if (l < 0) PERROR("read");
   		 if (DEBUG) {
   			 printf("\n(plain) payload: ");
   			 for(i = 0; i < l; i++) printf("%02x", *(buf+i));
   			 printf("\n");
   		 }
		 genIV(IV);
   		 if (do_crypt(KEY, IV, buf, &l, 1)) {
			 if (DEBUG) {
   				 for(i = 0; i < l; i++) printf("%02x", *(buf+i));
   				 printf("\n");
   			 }
   			 appendHMAC(buf, &l);    // append HMAC here
   			 appendIV(buf,IV,&l);
			 
			 memset(KEY,'\0',KEY_IV_SIZE);
			 memset(IV,'\0',KEY_IV_SIZE);

			 if (DEBUG) {
   				 printf("\n(final) payload: ");
   				 for(i = 0; i < l; i++) printf("%02x", *(buf+i));
   				 printf("\n");
   			 }
   			 if (sendto(s, buf, l, 0, (struct sockaddr *)&sout, soutlen) < 0) PERROR("sendto");
   		 }
   		 else {
   			 printf("Encryption fail.  Drop packet.\n");
   		 }
   	 }
   	 else {
   		 if (DEBUG) printf("\n RECEIVED << ");
   		 l = recvfrom(s, buf, BUFF_SIZE, 0, (struct sockaddr *)&sout, &soutlen);
   		 if (DEBUG) {
   			 printf("\n(encrypted) payload: ");
   			 for(i = 0; i < l; i++) printf("%02x", *(buf+i));
   			 printf("\n");
   		 }
   		 if (checkHMAC(buf, &l)) {    // check HMAC
   			 printf("HMAC mismatch.  Drop packet.\n");
   		 }
   		 else {
		 
		 if (checkIV(buf,IV,&l)) {    // check HMAC
			  printf("HMAC2 mismatch.  Drop packet.\n");
		}
		else{
   			 if (DEBUG) {
   				 printf("\n(hmac checked) payload: ");
   				 for(i = 0; i < l; i++) printf("%02x", *(buf+i));
   				 printf("\n");
   			 }
   			 // decryption
   			 if (do_crypt(KEY, IV, buf, &l, 0)) {
   				 if (DEBUG) {
   					 printf("\n(final plain) payload: ");
   					 for(i = 0; i < l; i++) printf("%02x", *(buf+i));
   					 printf("\n");
   				 }
   				 
				 if (write(fd, buf, l) < 0) {
					PERROR("write");
				}
				
				memset(KEY,'\0',KEY_IV_SIZE);
				memset(IV,'\0',KEY_IV_SIZE);

   			 }
   			 else {
   				 printf("Decryption fail.  Drop packet.\n");
   			 }
   		 }
		}
   	 }
    }
}

int main(int argc, char *argv[]) {
    int remote_port, listen_port;
    char c, *p, *ip;
    int fd[2];
    pid_t pid;
    char buf[1024];
    int MODE = 0, i = 0;

    while ((c = getopt(argc, argv, "s:c:h")) != -1) {
   	 switch (c) {
   	 case 's':    // server mode
   		 MODE = 1;
   		 listen_port = atoi(optarg);
   		 break;
   	 case 'c':    // client mode
   		 MODE = 2;
		 strcpy(SER_CERT_CN,argv[3]);
   		 p = (char *)memchr(optarg,':',16);
   		 if (!p) ERROR("invalid argument : [%s]\n", optarg);
   		 *p = 0;
   		 ip = optarg;
   		 remote_port = atoi(p+1);
   		 listen_port = 0;
   		 break;
   	 case 'h':    // by default
   	 default:
   		 usage();
   	 }
    }
    if (!MODE) usage();

    pipe(fd);
	fcntl(fd[0], F_SETFL, O_NONBLOCK);
    fcntl(fd[1], F_SETFL, O_NONBLOCK);

    if((pid = fork()) < 0) {
   	 PERROR("fork");
    }
    else if (pid > 0) { // parent process, for PKI
   	 close(fd[0]);
   	 switch (MODE) {
   	 case 1:
   		 keyXchange_server(listen_port, KEY, IV, fd[1], pid);
   		 break;
   	 case 2:
   		 genKey(KEY);
   		 genIV(IV);
   		 keyXchange_client(ip, remote_port, SER_CERT_CN, KEY, IV, fd[1], pid);
   		 break;
   	 }
   	 printf("Parent process quit!\n");
    }
    else {
   	 close(fd[1]);
   	 startVPN(MODE, listen_port, ip, remote_port, fd[0]);
   	 printf("Child process quit!\n");
    }
}
