#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

//[실행파일명 (-e, -d) (ecb,cbc) 암호화 할 파일명]
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



void teaEncrypt(unsigned int v[], unsigned int k[]) {	//	TEA 암호화 알고리즘 
	int sum = 0;
	for (int i = 0; i < 32; i++) {
		sum += 0x9e3779b9;
		v[0] += (v[1] + sum) ^ ((v[1] << 4) + k[0]) ^ ((v[1] >> 5) + k[1]);
		v[1] += (v[0] + sum) ^ ((v[0] << 4) + k[2]) ^ ((v[0] >> 5) + k[3]);
	}
}

void teaDecrypt(unsigned int v[], unsigned int k[]) {	//	TEA 복호화 알고리즘
	int sum = 0;
	for(int i=0; i<32; i++)
		sum += 0x9e3779b9;
		
	for (int i = 0; i < 32; i++) {
		v[1] -= (v[0] + sum) ^ ((v[0] << 4) + k[2]) ^ ((v[0] >> 5) + k[3]);
		v[0] -= (v[1] + sum) ^ ((v[1] << 4) + k[0]) ^ ((v[1] >> 5) + k[1]);
		sum -= 0x9e3779b9;
	}
}
//	TEA ECB모드 암호화 함수 
// 헤더 암호화 후 원문 내용 암호화 
void encrypt_ECB(char *fileName, unsigned int key[]) {	
 
	substitute header; //헤더 공용체 
	substitute Content; // 원문 공용체 
	char createFileName[128]; // 새로만들 파일 
	char copyHeader[8] = { 'T', 'E', 'A', 0, 'E', 'C', 'B', 0 }; // 헤더 정의 

	
	FILE *bfFileDes = fopen(fileName, "rb");		//암호화할 파일 읽기 
	strcpy(createFileName, fileName);
	strcat(createFileName, ".tea");					// 파일 이름에 .tea 추가 
	FILE *afFileDes = fopen(createFileName, "wb");	 //쓰기모드로 새파일 만들기 
	
	
	
	for (int i = 0; i < 8; i++)	{
		header.charBlock[i] = copyHeader[i];
	}//헤더에 TEA0ECB0 복사	
	teaEncrypt(header.intBlock, key); //헤더 암호화  
	fwrite(&header, 1, 8, afFileDes); //헤더 쓰 기 
	

	while (1) { //원문 내용 암호화 
	
		int readByte = fread(&Content, 1, 8, bfFileDes);

		Content.charBlock[8] = '\0'; 
		if(readByte == 0) //파일 끝까지 읽을경우 break 
        {
        	printf("-------------------------------------------\n");
            break;
        }
		teaEncrypt(Content.intBlock, key);
		fwrite(&Content, 1, 8, afFileDes); //암호화한 원문 쓰기 
	}
	printf("파일이 암호화되었습니다.\n");
	
	fclose(bfFileDes); // 파일 close 
	fclose(afFileDes);

}

void decrypt_ECB(char *fileName, unsigned int key[]) {	//	TEA ECB 모드 복호화
 
	substitute header;
	substitute Content;

	FILE *bfFileDes = fopen(fileName, "rb");
	char createFileName[128];
	for (int i = 0; i < strlen(fileName) - 4; i++)	// .tea 제거
		createFileName[i] = fileName[i];
	createFileName[strlen(fileName) - 4] = '\0';	//	문자열 마지막 널
	FILE *afFileDes = fopen(createFileName, "wb");

	
	int readByte = fread(&header, 1, 8, bfFileDes);
	
	teaDecrypt(header.intBlock, key); //입력받은 key 로  복호화 후  header 비교하여 복호화 성공여부 판단 
	if (header.charBlock[0] == 'T' &&
		header.charBlock[1] == 'E' &&
		header.charBlock[2] == 'A' &&
		header.charBlock[3] == 0 &&
		header.charBlock[4] == 'E' &&
		header.charBlock[5] == 'C' &&
		header.charBlock[6] == 'B' &&
		header.charBlock[7] == 0) {
		printf("비밀번호가 일치합니다. 복호화 진행합니다.\n");
	}
	else {
		printf("비밀번호가 일치하지 않습니다.");
		exit(1);
	}
	// 암호화된 내용 복호화 
	while (1) {
		readByte = fread(&Content, 1, 8, bfFileDes);
		Content.charBlock[8] = '\0';
		
		if(readByte == 0)
        {
        	printf("-------------------------------------------\n");
            break;
        }
		teaDecrypt(Content.intBlock, key); //암호화된 내용 읽은후 복호화 
		fwrite(&Content, 1, 8, afFileDes);//복호화 후 파일에 쓰기 
	}
	printf("파일이 복호화 되었습니다.\n");

	fclose(bfFileDes);
	fclose(afFileDes);

}

void encrypt_CBC(char *fileName, unsigned int key[]) {	// CBC모드 암호화 

	substitute header;
	substitute Content;
	char copyHeader[8] = { 'T', 'E', 'A', 0, 'C', 'B', 'C', 0 };
	substitute preContent; //이전 인덱스를 저장할 preContent 생성 
	
	substitute IV; //IV 생성후 랜덤 값 부여 
	IV.intBlock[0] = rand();
	IV.intBlock[1] = rand();
	
	FILE *bfFileDes = fopen(fileName, "rb"); //암호화된 파일 읽기 
	char createFileName[128];
	strcpy(createFileName, fileName);
	strcat(createFileName, ".tea");
	FILE *afFileDes = fopen(createFileName, "wb"); //쓰기모드로 새 파일 생성 



	for (int i = 0; i < 8; i++)	 
		header.charBlock[i] = copyHeader[i];	
	teaEncrypt(header.intBlock, key); //헤더 암호화 
	fwrite(&IV, 1, 8, afFileDes); //IV 와 헤더 쓰기 
	fwrite(&header, 1, 8, afFileDes);


	while(1) {
		int readByte = fread(&Content, 1, 8, bfFileDes);
		int cnt=0;
		Content.charBlock[8] = '\0'; 
		if(readByte == 0) // 파일을 끝까지 읽을경우 break 
        {   printf("-------------------------------------------\n");
            break;
        }
        if(cnt==0){//처음 C0 암호화 C0^IV 
        	for(int i=0; i<2; i++){
        		Content.intBlock[i] ^= IV.intBlock[i];
			}       	
        	cnt++;
		}else{ //C1 부터  이전 인텍스와 체인  C1^C0, C2^C1
			for(int i=0; i<2; i++){
				Content.intBlock[i] ^= preContent.intBlock[i];
		}
		
		}  
		preContent = Content; //새 내용을 읽어오기전 이전 내용을 preContent에 저장 
		teaEncrypt(Content.intBlock, key);
		fwrite(&Content, 1, 8, afFileDes);
	}
	printf("파일이 암호화되었습니다.\n");
	
	fclose(bfFileDes);
	fclose(afFileDes);

}

void decrypt_CBC(char *fileName, unsigned int key[]) {	//	CBC 모드 복호화 함수 

	substitute header;
	substitute Content;
	substitute IV; //이니셜 벡터 
	substitute preContent; //이전 인덱스를 저장할 preContent 
	char createFileName[128];
	
	FILE *bfFileDes = fopen(fileName, "rb");
	
	//파일 이름 변경 
	for (int i = 0; i < strlen(fileName) - 4; i++)	// .tea 제거
		createFileName[i] = fileName[i];
	createFileName[strlen(fileName) - 4] = '\0';	//	문자열 마지막 널
	FILE *afFileDes = fopen(createFileName, "wb");
	
	
	fread(&IV, 1, 8, bfFileDes);	//	IV와 Header 읽어오기 
	fread(&header, 1, 8, bfFileDes);
 	
	teaDecrypt(header.intBlock, key);
	
	if (header.charBlock[0] == 'T' &&	//복호화 된 헤더 확인 
		header.charBlock[1] == 'E' &&
		header.charBlock[2] == 'A' &&
		header.charBlock[3] == 0 &&
		header.charBlock[4] == 'C' &&
		header.charBlock[5] == 'B' &&
		header.charBlock[6] == 'C' &&
		header.charBlock[7] == 0) {
		printf("비밀번호가 일치합니다. 복호화 진행합니다.\n");
	}else {
		printf("비밀번호가 일치하지 않습니다.");
		exit(1);
	}

	while(1) { //암호화된 파일을 읽어온다 
		int readByte = fread(&Content, 1, 8, bfFileDes);
		
		if(readByte == 0){
			printf("-------------------------------------------\n");
            break;
        }
		Content.charBlock[8] = '\0';
		
		int cnt = 0;
		
		teaDecrypt(Content.intBlock, key); //암호화된 파일 복호화 
		if(cnt == 0) {	//IV를 이용하여 처음 C0 복호화 	C0^IV 
			for(int i=0; i<2; i++){
	        		Content.intBlock[i] ^= IV.intBlock[i];
			}  	
			cnt++;//count++해주어 C0복호화로 들어오지 않게 한다		
		}else {	// C1 부터 C2,C3 순서대로 복호화 C1^C0, C2^C1...
			for(int i=0; i<2; i++){ //이전인덱스의 preContent와 현재 인덱스의 Content와 XOR 
				Content.intBlock[i] ^= preContent.intBlock[i];
			}	
		}
		preContent=Content;//이전내용 preContent에 저장 
		fwrite(&Content, 1, 8, afFileDes);		
	}
	printf("파일이 복호화 되었습니다.\n");
		
	fclose(bfFileDes);
	fclose(afFileDes);	
}

void pass_check(char pass[]) {	//	비밀번호 확인 함수 

	char check[17];

	while (1) {
		printf("[확인] 비밀번호를 한번 더 입력하세요 : ");
		scanf("%s", check);
		for (int i = strlen(check); i < 16; i++)	//모자란 비밀번호자리 0으로 패딩 
			check[i] = '0';
		check[16] = '\0';
		if (!(strncmp(pass, check, 16))) break;	
		else printf("비밀번호가 틀렸습니다.\n");
	}
	printf("-----확인 되었습니다-----\n");
}


int main(int argc, char *argv[]) {
	
	convertKey key;
	char userPass[17];


	do {printf("[-----------FILE_Encrypt_Decrypt-----------]\n파일 비밀번호를 입력하세요 : ");
		scanf("%s", userPass);
		
	}while (strlen(userPass) < 10);
	
	for (int i = strlen(userPass); i < 16; i++)	//	모자라는 비밀번호 자리 0으로 패딩 
		userPass[i] = '0';
	userPass[16] = '\0';

	for (int i = 0; i < 16; i++)
		key.stringKey[i] = userPass[i];
	key.stringKey[16] = '\0';
	
	
	
	if (argc < 4) {
		printf("잘못된 실행입니다");
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
		printf("잘못된 실행입니다");
		exit(-1);
		}
	}
	
	else if (!strcmp(argv[1], "-d")) {
		if (!strcmp(argv[2], "ecb")){
			decrypt_ECB(argv[3], key.intKey);	
		}else if (!strcmp(argv[2], "cbc")){
			decrypt_CBC(argv[3], key.intKey);		
		}else {
		printf("잘못된 실행입니다");
		exit(-1);
		}
	}else {
		printf("잘못된 실행입니다");
		exit(-1);
	}
	
}

