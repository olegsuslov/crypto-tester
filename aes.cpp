#include "EM_AES.h"
unsigned char EM_AES::m_key[16] = {0};
string EM_AES::m_key_str = "";

EM_AES::EM_AES()
{
}

EM_AES::~EM_AES()
{
}

/**
 * EM_AES::set_key()
 * 设置AES加密密钥
 * 
 * @param string key
 * @return void
 */
void EM_AES::set_key(const string & key)
{
	this->m_key_str = key;
	
	unsigned char md[MD5_DIGEST_LENGTH];
	
	EVP_Digest(key.c_str(), (size_t)key.length(), md, NULL, EVP_md5(), NULL);

	strncpy((char*)&this->m_key, (char*)&md, EM_AES_KEY_SIZE/8); 
}

/**
 * EM_AES::get_key_str()
 * 获取AES加密/解密密钥的string
 * 
 * @return string 
 */
string EM_AES::get_key_str()
{
	return this->m_key_str;
}

/**
 * EM_AES::_init_key()
 * 初始化加密/解密密钥
 * 
 * @param int 
 * @return void
 */
void EM_AES::_init_key(int act=AES_ENCRYPT)
{
	if (act)
		AES_set_encrypt_key(this->m_key, EM_AES_KEY_SIZE, &this->m_aes_key);
	else
		AES_set_decrypt_key(this->m_key, EM_AES_KEY_SIZE, &this->m_aes_key);
}

struct EM_AESFILE EM_AES::encrypt(const string & inputfile)
{
	// 检查设置密钥
	this->_init_key(AES_ENCRYPT);

	// ifstream 读入文件
	ifstream fs_in(inputfile.c_str(), ios::in|ios::binary);
	
	if (!fs_in)
		throw (string)"文件读取时发生错误...";
	// 计算文件大小
	fs_in.seekg(0, ios::end);
	int size = fs_in.tellg();
	
	if (size > EM_MAX_FILE_SIZE)
		throw (string) "文件大小超过限制...";
	
	// 计算填充值大小
	int padsize = ( (EM_AES_KEY_SIZE/8) - size % (EM_AES_KEY_SIZE/8) ) % (EM_AES_KEY_SIZE/8);
	
	// 计算总空间
	int totalsize = size+padsize;
	
	// 分配内存空间
	char* tmp_in  = new char[totalsize]; 
	unsigned char* u_tmp_in = new unsigned char[totalsize];
	
	char* tmp_out = new char[totalsize];
	unsigned char* u_tmp_out = new unsigned char[totalsize];

	// 读入文件内容
	fs_in.seekg(0, ios::beg);
	fs_in.read(tmp_in, size);
	
	fs_in.close();
		
	// 用memcpy搞定 unsigned char* 和 char*的转换，太恶心了
	// 两天就耗在这里了

	// 填充为\0
	memset(u_tmp_in, 0, totalsize);
	// 内存复制
	memcpy(u_tmp_in, tmp_in, size);
	
	int i=0;
	int j=0;

	unsigned char tmp[AES_BLOCK_SIZE] = {0};
	unsigned char tmp2[AES_BLOCK_SIZE] = {0};

	// 按AES_BLOCK_SIZE来循环
	for (i=0; i<totalsize; i+=AES_BLOCK_SIZE)
	{
	//	cout << "Block" << i/AES_BLOCK_SIZE << endl;
		// 每次对block 内存拷贝
		for (j=0; j<AES_BLOCK_SIZE; j++)
		{
			tmp[j] = u_tmp_in[i+j];
	//		printf("%02x ", tmp[j]);	
		}
		
		// 块加密
		AES_encrypt(tmp, tmp2, &this->m_aes_key);
		
		// 加密后的数据复制到目标空间
		for (j=0; j<AES_BLOCK_SIZE; j++)
		{
			u_tmp_out[i+j] = tmp2[j];
		//	printf("%02X ", tmp2[j]);
		}
	}

	// unsigned char* -> char*
	memcpy(tmp_out, u_tmp_out, totalsize);

	string outputfile = EM_TMP_FILENAME;
	ofstream fs_out;
	fs_out.open(outputfile.c_str(), ios::out|ios::binary);
	fs_out.write(tmp_out, totalsize);
	fs_out.close();
	
	delete[] tmp_in;
	delete[] tmp_out;
	delete[] u_tmp_in;
	delete[] u_tmp_out;

	//free(tmp);
	//free(tmp2);
	
	struct EM_AESFILE aesfile = 
	{
		inputfile,
		padsize,
	};

	return aesfile;
}


void EM_AES::decrypt(struct EM_AESFILE & aesfile)
{	
	this->_init_key(AES_DECRYPT);

	string inputfile = EM_TMP_FILENAME;
	
	// ifstream 读入文件
	ifstream fs_in(inputfile.c_str(), ios::in|ios::binary);
	
	if (!fs_in)
		throw (string)"文件读取时发生错误...";
	// 计算文件大小
	fs_in.seekg(0, ios::end);
	int size = fs_in.tellg();
	
	if (size > EM_MAX_FILE_SIZE)
		throw (string) "文件大小超过限制...";
	else if (size % AES_BLOCK_SIZE != 0)
		throw (string) "输入的文件不是AES块的整数倍大小...";
		
	char* tmp_in = new char[size];
	unsigned char* u_tmp_in = new unsigned char[size];
	
	unsigned char* u_tmp_out = new unsigned char[size];
	char* tmp_out = new char[size-aesfile.padsize];
	
	fs_in.seekg(0, ios::beg);
	fs_in.read(tmp_in, size);
	fs_in.close();
	
	memcpy(u_tmp_in, tmp_in, size);
	
	int i=0;
	int j=0;
	
	unsigned char tmp[AES_BLOCK_SIZE] = {0};
	unsigned char tmp2[AES_BLOCK_SIZE] = {0};

	// 按AES_BLOCK_SIZE来循环
	for (i=0; i<size; i+=AES_BLOCK_SIZE)
	{
		// 每次对block 内存拷贝
		for (j=0; j<AES_BLOCK_SIZE; j++)
		{
			tmp[j] = u_tmp_in[i+j];
		}
		// 块加密
		AES_decrypt( tmp, tmp2, &this->m_aes_key);
		// 加密后的数据复制到目标空间
		for (j=0; j<AES_BLOCK_SIZE; j++)
		{
			u_tmp_out[i+j] = tmp2[j];
		}
	}

	memcpy(tmp_out, u_tmp_out, size-aesfile.padsize);
	
	ofstream fs_out(aesfile.filename.c_str(), ios::out|ios::binary);
	fs_out.write(tmp_out, size-aesfile.padsize);
	fs_out.close();
	
	delete[] tmp_in;
	delete[] tmp_out;
	delete[] u_tmp_in;
	delete[] u_tmp_out;
}

