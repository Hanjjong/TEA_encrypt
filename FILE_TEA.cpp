#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

//[�������ϸ� (-e, -d) (ecb,cbc) ��ȣȭ �� ���ϸ�]
//[example.exe -e ecb example.pdf] Encrypt
//[example.exe -d ecb example.pdf.tea] Decrypt

typedef union {
	unsigned char stringKey[17];	
	unsigned int intKey[4];	
} convertKey;

typedef union {
	unsigned char charBlock[8];	
	unsigned int intBlock[2];
}substitute;



void teaEncrypt(unsigned int v[], unsigned int k[]) {	//	TEA ��ȣȭ �˰��� 
	int sum = 0;
	for (int i = 0; i < 32; i++) {
		sum += 0x9e3779b9;
		v[0] += (v[1] + sum) ^ ((v[1] << 4) + k[0]) ^ ((v[1] >> 5) + k[1]);
		v[1] += (v[0] + sum) ^ ((v[0] << 4) + k[2]) ^ ((v[0] >> 5) + k[3]);
	}
}

void teaDecrypt(unsigned int v[], unsigned int k[]) {	//	TEA ��ȣȭ �˰���
	int sum = 0;
	for(int i=0; i<32; i++)
		sum += 0x9e3779b9;
		
	for (int i = 0; i < 32; i++) {
		v[1] -= (v[0] + sum) ^ ((v[0] << 4) + k[2]) ^ ((v[0] >> 5) + k[3]);
		v[0] -= (v[1] + sum) ^ ((v[1] << 4) + k[0]) ^ ((v[1] >> 5) + k[1]);
		sum -= 0x9e3779b9;
	}
}
//	TEA ECB��� ��ȣȭ �Լ� 
// ��� ��ȣȭ �� ���� ���� ��ȣȭ 
void encrypt_ECB(char *fileName, unsigned int key[]) {	
 
	substitute header; //��� ����ü 
	substitute Content; // ���� ����ü 
	char createFileName[128]; // ���θ��� ���� 
	char copyHeader[8] = { 'T', 'E', 'A', 0, 'E', 'C', 'B', 0 }; // ��� ���� 

	
	FILE *bfFileDes = fopen(fileName, "rb");		//��ȣȭ�� ���� �б� 
	strcpy(createFileName, fileName);
	strcat(createFileName, ".tea");					// ���� �̸��� .tea �߰� 
	FILE *afFileDes = fopen(createFileName, "wb");	 //������� ������ ����� 
	
	
	
	for (int i = 0; i < 8; i++)	{
		header.charBlock[i] = copyHeader[i];
	}//����� TEA0ECB0 ����	
	teaEncrypt(header.intBlock, key); //��� ��ȣȭ  
	fwrite(&header, 1, 8, afFileDes); //��� �� �� 
	

	while (1) { //���� ���� ��ȣȭ 
	
		int readByte = fread(&Content, 1, 8, bfFileDes);

		Content.charBlock[8] = '\0'; 
		if(readByte == 0) //���� ������ ������� break 
        {
        	printf("-------------------------------------------\n");
            break;
        }
		teaEncrypt(Content.intBlock, key);
		fwrite(&Content, 1, 8, afFileDes); //��ȣȭ�� ���� ���� 
	}
	printf("������ ��ȣȭ�Ǿ����ϴ�.\n");
	
	fclose(bfFileDes); // ���� close 
	fclose(afFileDes);

}

void decrypt_ECB(char *fileName, unsigned int key[]) {	//	TEA ECB ��� ��ȣȭ
 
	substitute header;
	substitute Content;

	FILE *bfFileDes = fopen(fileName, "rb");
	char createFileName[128];
	for (int i = 0; i < strlen(fileName) - 4; i++)	// .tea ����
		createFileName[i] = fileName[i];
	createFileName[strlen(fileName) - 4] = '\0';	//	���ڿ� ������ ��
	FILE *afFileDes = fopen(createFileName, "wb");

	
	int readByte = fread(&header, 1, 8, bfFileDes);
	
	teaDecrypt(header.intBlock, key); //�Է¹��� key ��  ��ȣȭ ��  header ���Ͽ� ��ȣȭ �������� �Ǵ� 
	if (header.charBlock[0] == 'T' &&
		header.charBlock[1] == 'E' &&
		header.charBlock[2] == 'A' &&
		header.charBlock[3] == 0 &&
		header.charBlock[4] == 'E' &&
		header.charBlock[5] == 'C' &&
		header.charBlock[6] == 'B' &&
		header.charBlock[7] == 0) {
		printf("��й�ȣ�� ��ġ�մϴ�. ��ȣȭ �����մϴ�.\n");
	}
	else {
		printf("��й�ȣ�� ��ġ���� �ʽ��ϴ�.");
		exit(1);
	}
	// ��ȣȭ�� ���� ��ȣȭ 
	while (1) {
		readByte = fread(&Content, 1, 8, bfFileDes);
		Content.charBlock[8] = '\0';
		
		if(readByte == 0)
        {
        	printf("-------------------------------------------\n");
            break;
        }
		teaDecrypt(Content.intBlock, key); //��ȣȭ�� ���� ������ ��ȣȭ 
		fwrite(&Content, 1, 8, afFileDes);//��ȣȭ �� ���Ͽ� ���� 
	}
	printf("������ ��ȣȭ �Ǿ����ϴ�.\n");

	fclose(bfFileDes);
	fclose(afFileDes);

}

void encrypt_CBC(char *fileName, unsigned int key[]) {	// CBC��� ��ȣȭ 

	substitute header;
	substitute Content;
	char copyHeader[8] = { 'T', 'E', 'A', 0, 'C', 'B', 'C', 0 };
	substitute preContent; //���� �ε����� ������ preContent ���� 
	
	substitute IV; //IV ������ ���� �� �ο� 
	IV.intBlock[0] = rand();
	IV.intBlock[1] = rand();
	
	FILE *bfFileDes = fopen(fileName, "rb"); //��ȣȭ�� ���� �б� 
	char createFileName[128];
	strcpy(createFileName, fileName);
	strcat(createFileName, ".tea");
	FILE *afFileDes = fopen(createFileName, "wb"); //������� �� ���� ���� 



	for (int i = 0; i < 8; i++)	 
		header.charBlock[i] = copyHeader[i];	
	teaEncrypt(header.intBlock, key); //��� ��ȣȭ 
	fwrite(&IV, 1, 8, afFileDes); //IV �� ��� ���� 
	fwrite(&header, 1, 8, afFileDes);


	while(1) {
		int readByte = fread(&Content, 1, 8, bfFileDes);
		int cnt=0;
		Content.charBlock[8] = '\0'; 
		if(readByte == 0) // ������ ������ ������� break 
        {   printf("-------------------------------------------\n");
            break;
        }
        if(cnt==0){//ó�� C0 ��ȣȭ C0^IV 
        	for(int i=0; i<2; i++){
        		Content.intBlock[i] ^= IV.intBlock[i];
			}       	
        	cnt++;
		}else{ //C1 ����  ���� ���ؽ��� ü��  C1^C0, C2^C1
			for(int i=0; i<2; i++){
				Content.intBlock[i] ^= preContent.intBlock[i];
		}
		
		}  
		preContent = Content; //�� ������ �о������ ���� ������ preContent�� ���� 
		teaEncrypt(Content.intBlock, key);
		fwrite(&Content, 1, 8, afFileDes);
	}
	printf("������ ��ȣȭ�Ǿ����ϴ�.\n");
	
	fclose(bfFileDes);
	fclose(afFileDes);

}

void decrypt_CBC(char *fileName, unsigned int key[]) {	//	CBC ��� ��ȣȭ �Լ� 

	substitute header;
	substitute Content;
	substitute IV; //�̴ϼ� ���� 
	substitute preContent; //���� �ε����� ������ preContent 
	char createFileName[128];
	
	FILE *bfFileDes = fopen(fileName, "rb");
	
	//���� �̸� ���� 
	for (int i = 0; i < strlen(fileName) - 4; i++)	// .tea ����
		createFileName[i] = fileName[i];
	createFileName[strlen(fileName) - 4] = '\0';	//	���ڿ� ������ ��
	FILE *afFileDes = fopen(createFileName, "wb");
	
	
	fread(&IV, 1, 8, bfFileDes);	//	IV�� Header �о���� 
	fread(&header, 1, 8, bfFileDes);
 	
	teaDecrypt(header.intBlock, key);
	
	if (header.charBlock[0] == 'T' &&	//��ȣȭ �� ��� Ȯ�� 
		header.charBlock[1] == 'E' &&
		header.charBlock[2] == 'A' &&
		header.charBlock[3] == 0 &&
		header.charBlock[4] == 'C' &&
		header.charBlock[5] == 'B' &&
		header.charBlock[6] == 'C' &&
		header.charBlock[7] == 0) {
		printf("��й�ȣ�� ��ġ�մϴ�. ��ȣȭ �����մϴ�.\n");
	}else {
		printf("��й�ȣ�� ��ġ���� �ʽ��ϴ�.");
		exit(1);
	}

	while(1) { //��ȣȭ�� ������ �о�´� 
		int readByte = fread(&Content, 1, 8, bfFileDes);
		
		if(readByte == 0){
			printf("-------------------------------------------\n");
            break;
        }
		Content.charBlock[8] = '\0';
		
		int cnt = 0;
		
		teaDecrypt(Content.intBlock, key); //��ȣȭ�� ���� ��ȣȭ 
		if(cnt == 0) {	//IV�� �̿��Ͽ� ó�� C0 ��ȣȭ 	C0^IV 
			for(int i=0; i<2; i++){
	        		Content.intBlock[i] ^= IV.intBlock[i];
			}  	
			cnt++;//count++���־� C0��ȣȭ�� ������ �ʰ� �Ѵ�		
		}else {	// C1 ���� C2,C3 ������� ��ȣȭ C1^C0, C2^C1...
			for(int i=0; i<2; i++){ //�����ε����� preContent�� ���� �ε����� Content�� XOR 
				Content.intBlock[i] ^= preContent.intBlock[i];
			}	
		}
		preContent=Content;//�������� preContent�� ���� 
		fwrite(&Content, 1, 8, afFileDes);		
	}
	printf("������ ��ȣȭ �Ǿ����ϴ�.\n");
		
	fclose(bfFileDes);
	fclose(afFileDes);	
}

void pass_check(char pass[]) {	//	��й�ȣ Ȯ�� �Լ� 

	char check[17];

	while (1) {
		printf("[Ȯ��] ��й�ȣ�� �ѹ� �� �Է��ϼ��� : ");
		scanf("%s", check);
		for (int i = strlen(check); i < 16; i++)	//���ڶ� ��й�ȣ�ڸ� 0���� �е� 
			check[i] = '0';
		check[16] = '\0';
		if (!(strncmp(pass, check, 16))) break;	
		else printf("��й�ȣ�� Ʋ�Ƚ��ϴ�.\n");
	}
	printf("-----Ȯ�� �Ǿ����ϴ�-----\n");
}


int main(int argc, char *argv[]) {
	
	convertKey key;
	char userPass[17];


	do {printf("[-----------FILE_Encrypt_Decrypt-----------]\n���� ��й�ȣ�� �Է��ϼ��� : ");
		scanf("%s", userPass);
		
	}while (strlen(userPass) < 10);
	
	for (int i = strlen(userPass); i < 16; i++)	//	���ڶ�� ��й�ȣ �ڸ� 0���� �е� 
		userPass[i] = '0';
	userPass[16] = '\0';

	for (int i = 0; i < 16; i++)
		key.stringKey[i] = userPass[i];
	key.stringKey[16] = '\0';
	
	
	
	if (argc < 4) {
		printf("�߸��� �����Դϴ�");
		exit(-1);
	}
	
	if (!strcmp(argv[1], "-e")){
		if (!strcmp(argv[2], "ecb")){
			pass_check(userPass);
			encrypt_ECB(argv[3], key.intKey);	
		}else if (!strcmp(argv[2], "cbc")){
			pass_check(userPass);
			encrypt_CBC(argv[3], key.intKey);		
		}else {
		printf("�߸��� �����Դϴ�");
		exit(-1);
		}
	}
	
	else if (!strcmp(argv[1], "-d")) {
		if (!strcmp(argv[2], "ecb")){
			decrypt_ECB(argv[3], key.intKey);	
		}else if (!strcmp(argv[2], "cbc")){
			decrypt_CBC(argv[3], key.intKey);		
		}else {
		printf("�߸��� �����Դϴ�");
		exit(-1);
		}
	}else {
		printf("�߸��� �����Դϴ�");
		exit(-1);
	}
	
}

