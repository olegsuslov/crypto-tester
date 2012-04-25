#ifndef EM_AES_H_
#define EM_AES_H_

#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

#include <iostream>
#include <string>
#include <fstream>

#include "config.h"

using namespace std;

struct EM_AESFILE
{
	string filename;
	int    padsize;
};

class EM_AES
{
public:
	EM_AES();
	virtual ~EM_AES();
	void set_key(const string &);
	string get_key_str();
	
	struct EM_AESFILE encrypt(const string & inputfile);
	void decrypt(struct EM_AESFILE & em_aesfile);
	
private:
	void _init_key(int);
	
	AES_KEY m_aes_key;

	static unsigned char m_key[];
	static string m_key_str;	
};

#endif /*EM_AES_H_*/
