#include <stdio.h>
#include "yxyDES.h"

void main()
{
	yxyDES* my_des = new yxyDES();
	string test_string = "test des plaintext!";
	printf("first,we use the des:\n");
	//initialize key
	my_des->InitializeKey("12345678",false);
	printf("key is : 12345678 \n");
	//use des to encrypt
	my_des->EncryptAnyLength(test_string,false);
	printf("set plaintext : %s \n",test_string.c_str());
	//get the ciphertext
	test_string = my_des->GetCiphertextAnyLength();
	printf("after encrypt : %s \n",test_string.c_str());
	//use des to decrypt
	printf("now,decrypting...\n");
	my_des->DecryptAnyLength(test_string,false);
	test_string = my_des->GetPlaintextAnyLength();
	printf("after decrypt : %s \n",test_string.c_str());
	
	//use 3des
	printf("\n\nnow,let us use the 3des:\n");
	printf("before encrypt,test_string is : %s\n",test_string.c_str());
	//initialize the first key
	my_des->InitializeKey("12345678",false);
	printf("the first key is : 12345678 \n");
	//initialize the second key
	my_des->InitializeKey("87654321",true);
	printf("the second key is : 87654321 \n");
	//use 3des to encrypt
	my_des->TripleEncryptAnyLength(test_string);
	//get the ciphertext
	test_string = my_des->GetCiphertextAnyLength();
	printf("after encrypt : %s \n",test_string.c_str());
	//use the 3des to decrypt
	printf("now,(3des)decrypting...\n");
	my_des->TripleDecryptAnyLength(test_string);
	test_string = my_des->GetPlaintextAnyLength();
	printf("after (3des)decrypt : %s \n",test_string.c_str());
	getchar();
}