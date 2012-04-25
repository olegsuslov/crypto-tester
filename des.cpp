#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/des.h>
 
 
char *
Encrypt( char *Key, char *Msg, int size)
{
 
        static char*    Res;
        int             n=0;
        DES_cblock      Key2;
        DES_key_schedule schedule;
 
        Res = ( char * ) malloc( size );
 
        /* Prepare the key for use with DES_cfb64_encrypt */
        memcpy( Key2, Key,8);
        DES_set_odd_parity( &Key2 );
        DES_set_key_checked( &Key2, &schedule );
 
        /* Encryption occurs here */
        DES_cfb64_encrypt( ( unsigned char * ) Msg, ( unsigned char * ) Res,
                           size, &schedule, &Key2, &n, DES_ENCRYPT );
 
         return (Res);
}
 
 
char *
Decrypt( char *Key, char *Msg, int size)
{
 
        static char*    Res;
        int             n=0;
 
        DES_cblock      Key2;
        DES_key_schedule schedule;
 
        Res = ( char * ) malloc( size );
 
        /* Prepare the key for use with DES_cfb64_encrypt */
        memcpy( Key2, Key,8);
        DES_set_odd_parity( &Key2 );
        DES_set_key_checked( &Key2, &schedule );
 
        /* Decryption occurs here */
        DES_cfb64_encrypt( ( unsigned char * ) Msg, ( unsigned char * ) Res,
                           size, &schedule, &Key2, &n, DES_DECRYPT );
 
        return (Res);
 
}
