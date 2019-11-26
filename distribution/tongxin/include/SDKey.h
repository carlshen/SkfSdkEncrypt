/**
 * 量子项目SDK接口头文件
 * 1 具体实现参考C文件
 **/

#ifndef SD_KEY_H
#define SD_KEY_H

static const int VERSION_NAME_LEN = 8;
// result 0: success;  other: failure
int GetVersion (char* Version);
int InputKey (char* KeyData, int KeyOffset, int KeyLen);
int ReadKey (char* KeyData, int KeyOffset, int KeyLen);
int TransmitData (char* SendData, int SendLen, char* RecvData, int RecvLen);

#endif
