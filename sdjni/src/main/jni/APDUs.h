
#ifndef SKF_APDU_H
#define SKF_APDU_H

#include "skf_type.h"

#define SIZE_BUFFER_4          4
#define SIZE_BUFFER_8          8
#define SIZE_BUFFER_16         16
#define SIZE_BUFFER_24         24
#define SIZE_BUFFER_32         32
#define SIZE_BUFFER_64         64
#define SIZE_BUFFER_96         96
#define SIZE_BUFFER_128        128
#define SIZE_BUFFER_255        255
#define SIZE_BUFFER_256        256
#define SIZE_BUFFER_512        512
#define SIZE_BUFFER_1024       1024
#define SIZE_BUFFER_2048       2048

#define  SGD_SM1          0x00000100
#define  SGD_SM4          0x00000400
#define  SGD_SM1_ECB	  0x00000101	//SM1 ECB
#define  SGD_SM1_CBC	  0x00000102	//SM1 CBC
#define  SGD_SM1_CFB	  0x00000104	//SM1 CFB
#define  SGD_SM1_OFB	  0x00000108	//SM1 OFB
#define  SGD_SM1_MAC	  0x00000110	//SM1 MAC
#define  SGD_SSF33_ECB	  0x00000201	//SSF33 ECB
#define  SGD_SSF33_CBC	  0x00000202	//SSF33 CBC
#define  SGD_SSF33_CFB	  0x00000204	//SSF33 CFB
#define  SGD_SSF33_OFB	  0x00000208	//SSF33 OFB
#define  SGD_SSF33_MAC	  0x00000210	//SSF33 MAC
#define  SGD_SM4_ECB	  0x00000401	//SMS4 ECB
#define  SGD_SM4_CBC	  0x00000402	//SMS4 CBC
#define  SGD_SM4_CFB	  0x00000404	//SMS4 CFB
#define  SGD_SM4_OFB	  0x00000408	//SMS4 OFB
#define  SGD_SM4_MAC	  0x00000410    //SMS4 MAC

int SKF_WRITE_LOG_FILE;
int sv_Device;
#define REPEAT_TIMES       1
unsigned char KEY_HANDLE[SIZE_BUFFER_32];
CHAR SV_PSZLOGPATH[SIZE_BUFFER_128];

void WriteLogToFile( CHAR* szLog );

BYTE bRandomKey[16];
BYTE bKeyHandle[32];
BYTE bEccPrikey[32];
BYTE bEccPubkey[64];

//CA
BYTE APDU_CA_FID[2];
BYTE APDU_MF_FID[2];
BYTE APDU_EF01_FID[2];
BYTE APDU_EF02_FID[2];

BYTE apdu_selectDF[0x07];
BYTE apdu_updateBinary[0x05];
BYTE apdu_readBinary[0x05];

//Random, 0x05
BYTE apdu_random2[5];
//Response, 0x05
BYTE apdu_getResponse[5];

//ECC signature key pair
BYTE apdu_GenEccKeyPair[0x08];
BYTE apdu_eccGenKeyPair[0x05];
BYTE apdu_importEcc46[0x07];
BYTE apdu_importEcc26[0x07];
BYTE apdu_eccSignData[0x05];
BYTE apdu_eccSignVerify[0x05];
BYTE apdu_genDataKeyEcc[0x0D];
BYTE apdu_getDevInfo[0x05];
BYTE apdu_eccEncrypt[0x05];
BYTE apdu_eccDecrypt[0x05];
BYTE apdu_connect[0x07];
BYTE apdu_84_00[0x05];
BYTE apdu_A4_04[0x04];
BYTE apdu_A5_00[0x05];
BYTE apdu_B0_00[0x04];
BYTE apdu_C1_02[0x05];
BYTE apdu_C8_00[0x05];
BYTE apdu_C8_06[0x06];
BYTE apdu_C6_A0[0x05];
BYTE apdu_CA_05[0x05];
BYTE apdu_CC_00[0x04];
BYTE apdu_CE_00[0x04];
BYTE apdu_CE_01[0x05];
BYTE apdu_D1_02[0x05];
BYTE apdu_D6_00[0x04];
BYTE apdu_E1_00[0x05];
BYTE apdu_F1_00[0x04];
BYTE apdu_F1_40[0x05];
BYTE apdu_F4_00[0x04];
BYTE apdu_F8_01[0x04];
BYTE apdu_F8_02[0x04];
BYTE apdu_F8_03[0x04];
BYTE apdu_FA_00[0x04];
BYTE apdu_FA_01[0x05];
BYTE apdu_FA_02[0x04];
BYTE apdu_FA_03[0x04];
BYTE apdu_FA_06[0x05];
BYTE apdu_FC_01[0x06];
BYTE apdu_FC_02[0x04];
BYTE apdu_FC_03[0x04];
BYTE apdu_A001[0x02];
BYTE apdu_A002[0x02];
BYTE apdu_A101[0x02];
BYTE apdu_A102[0x02];
BYTE apdu_0001[0x02];
BYTE apdu_0002[0x02];
BYTE apdu_0010[0x02];
BYTE apdu_0020[0x02];
BYTE apdu_0040[0x02];
BYTE apdu_0800[0x02];
BYTE apdu_0107[0x02];
BYTE apdu_0200[0x02];
BYTE apdu_0207[0x02];
BYTE apdu_2007[0x02];
BYTE apdu_00[0x01];
BYTE apdu_01[0x01];
BYTE apdu_02[0x01];
BYTE apdu_03[0x01];
BYTE apdu_04[0x01];
BYTE apdu_06[0x01];
BYTE apdu_08[0x01];
BYTE apdu_16[0x01];
BYTE apdu_20[0x01];
BYTE apdu_26[0x01];
BYTE apdu_46[0x01];
BYTE apdu_80[0x01];
BYTE apdu_FF[0x01];

//SM1, encrypt, ECB model, 0x05
BYTE apdu_encrypt_sm1_ecb[0x05];
//SM1, decrypt, ECB model, 0x05
BYTE apdu_decrypt_sm1_ecb[0x05];
//SM1, encrypt, CBC model, 0x05
BYTE apdu_encrypt_sm1_cbc[0x05];
//SM1, decrypt, CBC model, 0x05
BYTE apdu_decrypt_sm1_cbc[0x05];
//SM1, encrypt, CFB model, 0x05
BYTE apdu_encrypt_sm1_cfb[0x05];
//SM1, decrypt, CFB model, 0x05
BYTE apdu_decrypt_sm1_cfb[0x05];
//SM1, encrypt, OFB model, 0x05
BYTE apdu_encrypt_sm1_ofb[0x05];
//SM1, decrypt, OFB model, 0x05
BYTE apdu_decrypt_sm1_ofb[0x05];

//SSF33, encrypt, ECB model, 0x05
BYTE apdu_encrypt_ssf33_ecb[0x05];
//SSF33, decrypt, ECB model, 0x05
BYTE apdu_decrypt_ssf33_ecb[0x05];
//SSF33, encrypt, CBC model, 0x05
BYTE apdu_encrypt_ssf33_cbc[0x05];
//SSF33, decrypt, CBC model, 0x05
BYTE apdu_decrypt_ssf33_cbc[0x05];
//SSF33, encrypt, CFB model, 0x05
BYTE apdu_encrypt_ssf33_cfb[0x05];
//SSF33, decrypt, CFB model, 0x05
BYTE apdu_decrypt_ssf33_cfb[0x05];
//SSF33, encrypt, OFB model, 0x05
BYTE apdu_encrypt_ssf33_ofb[0x05];
//SSF33, decrypt, OFB model, 0x05
BYTE apdu_decrypt_ssf33_ofb[0x05];

//SM4, encrypt, ECB model, 0x05
BYTE apdu_encrypt_sm4_ecb[0x05];
//SM4, decrypt, ECB model, 0x05
BYTE apdu_decrypt_sm4_ecb[0x05];
//SM4, encrypt, CBC model, 0x05
BYTE apdu_encrypt_sm4_cbc[0x05];
//SM4, decrypt, CBC model, 0x05
BYTE apdu_decrypt_sm4_cbc[0x05];
//SM4, encrypt, CFB model, 0x05
BYTE apdu_encrypt_sm4_cfb[0x05];
//SM4, decrypt, CFB model, 0x05
BYTE apdu_decrypt_sm4_cfb[0x05];
//SM4, encrypt, OFB model, 0x05
BYTE apdu_encrypt_sm4_ofb[0x05];
//SM4, decrypt, OFB model, 0x05
BYTE apdu_decrypt_sm4_ofb[0x05];

//group algorithm SM1, SSF33 and SM4, etc. CBC model, 0x05
BYTE apdu_cbc_sendIV[0x05];
//SM3 digest
BYTE apdu_sm3_digest[0x05];

#endif //SKF_APDU_H
