int main() {
 
char key[]="";
char clear[]="This is a secret message";
char *decrypted;
char *encrypted;
 
encrypted=malloc(sizeof(clear));
decrypted=malloc(sizeof(clear));
 
printf("Clear text\t : %s \n",clear);
memcpy(encrypted,Encrypt(key,clear,sizeof(clear)), sizeof(clear));
printf("Encrypted text\t : %s \n",encrypted);
memcpy(decrypted,Decrypt(key,encrypted,sizeof(clear)), sizeof(clear));
printf("Decrypted text\t : %s \n",decrypted);
 
 
 
return (0);
}