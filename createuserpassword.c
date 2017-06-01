#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <string.h>

#define SALTLENGTH 16
void generateHash(char *message,unsigned char *md_value);
void genRandomString(char *message, int flag);
char *Hextostring(unsigned char *hhex);
void writetoFile(char *userName,char *salt, unsigned char *md_value);
void ReadFromFile(char *enteredUName,char *enteredPwd);
int CheckValidUserID(char *userName);
int randomNbr(int hr);

void genRandomString(char *message, int flag)
{

	int randLength;
	int i=0;
	
	if(flag==1)// for salt
	{
		randLength = SALTLENGTH;
		for(i=0;i<randLength;i++)
		{
			message[i] = 65 + randomNbr(123456)%26;
		}
	}
	else
	{
		randLength = randomNbr(654321)%40;
		if(randLength<2)
		randLength += 1;

		for(i=0;i<randLength;i++)
		{
			message[i] = randomNbr(123456)%256;
		}
	}
	
	

	//printf("%d\n",randLength);
	//printf("%s\n",message);
	
}


void generateHash(char *message,unsigned char *md_value)
{
	 EVP_MD_CTX *mdctx;
	 const EVP_MD *md; 
	 
	unsigned int md_len, i;
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

	/*printf("Digest is: ");
	 for(i = 0; i < md_len; i++) printf("%02x", md_value[i]);
	 printf("\n"); */

}

int randomNbr(int highRange) 
{
       if(highRange>0)
	{
              static int randomSalt=30;
               srand(time(NULL)+randomSalt);
               int randomNumber = rand() % (highRange) +1;
               randomSalt++;
               return randomNumber;
       } 
	else
        return 1;
}

 
int CheckValidUserID(char *enteredUName)
{

	FILE *inputFilePtr; 
		inputFilePtr = fopen("file1.txt", "r");
		char readLine[100];
		char *userName;
		int count = 0;
		
		
		if(inputFilePtr == NULL)
		{
			printf("\nError opening the file file1.txt\n");
		}
		else
		{

			while(fgets(readLine,100,inputFilePtr)!=NULL)
			{
				if(strcmp(readLine,"\n"))
				{
					userName = strtok(readLine,",");		
					
					if(strcmp(userName,enteredUName)==0)					
					{
						//printf("username matched\n");
						return 1;
						break;
					}
				}										

			}

		}

		fclose(inputFilePtr);	
		return 0;

}


int  main(int argc, char *argv[])
 {	

	unsigned char md_value[EVP_MAX_MD_SIZE],md_value2[EVP_MAX_MD_SIZE];
	int index = 0;
	int breakCount =0, breakAvg =0;

	char password[36];
	char userName[40];

	printf("\nEnter Username:");
	scanf("%s",userName);

	if(CheckValidUserID(userName)==0)
	{
		printf("\nEnter Password:");
		scanf("%s",password);

		char *salt = (char *)malloc(sizeof(char)*SALTLENGTH);
		genRandomString(salt,1);
		//printf("%s\n",salt);
		strcat(password,salt);
		generateHash(password,md_value);

		writetoFile(userName,salt,md_value);
		printf("\nUser Registration successfull!!\n");
	}
	else
	{
		printf("\nUsername already exists!!!\n");
	}


	return 0;	 
 }

	


void writetoFile(char *userName,char *salt, unsigned char *md_value)
{
	FILE *f = fopen("file1.txt", "a");
	int i =0;
	if (f == NULL)
	{
	    printf("Error opening file!\n");
	    exit(1);
	}

	strcat(userName,",");
	strcat(userName,salt);
	strcat(userName,",");


	fprintf(f, "\n%s", userName);	
	for(i = 0; i < 32; i++) fprintf(f,"%x", md_value[i]);
		
	fclose(f);

}

void checkHash(char *enteredPwd, char *salt, char *pwdHash)
{


	unsigned char md_value[EVP_MAX_MD_SIZE];
	int i=0;
	int flag = 1;
	char *genHash = (char *)malloc(sizeof(char)*64);
	char *temp = (char *)malloc(sizeof(char));
	//enteredPwd
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
	/*if(strcmp(genHash,pwdHash)==0)
	{
		printf("\npassword matched!!!!!\n");
	}*/

	for(i = 0;i <64;i++)
	{

		if(pwdHash[i]!=genHash[i])
		{
			flag = 0;
			break;
		}

	}

	if(flag==0)
	printf("password not matched\n");
	else
	printf("password match\n");

	/*printf("%s\n",pwdHash);
	for(i = 0; i < 32; i++) printf("%02x", md_value[i]);*/

}

	void ReadFromFile(char *enteredUName,char *enteredPwd)
	{
		
		FILE *inputFilePtr; 
		inputFilePtr = fopen("file1.txt", "r");
		char readLine[100];
		char *userName;
		char *salt = (char *)malloc(sizeof(char) * SALTLENGTH); 
		char *pwdHash = (char *)malloc(sizeof(char) * 64); ;
		int count = 0;
		
		//char *foo = malloc(sizeof(char) * 1024); 
		//salt = (char *)malloc(2*sizeof(char));
		
		if(inputFilePtr == NULL)
		{
			printf("\nError opening the file file1.txt\n");
		}
		else
		{

			while(fgets(readLine,100,inputFilePtr)!=NULL)
			{
				if(strcmp(readLine,"\n"))
				{
					userName = strtok(readLine,",");		
					salt = strtok(NULL,",");		
					pwdHash = strtok(NULL,",");	

					/*printf("%s\n",userName);
					printf("%s\n",salt);
					printf("%s\n",pwdHash);*/
					if(strcmp(userName,enteredUName)==0)					
					{
						checkHash(enteredPwd,salt,pwdHash);
						printf("username matched\n");
						break;
					}
				}										

			}

		}

		fclose(inputFilePtr);		

	}


