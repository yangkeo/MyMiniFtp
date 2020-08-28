#ifndef _STR_H_
#define _STR_H_

#include "common.h"

void str_trim_crlf(char *str); //裁剪掉ftp协议命令格式中的\n\r
void str_split(const char *str, char *left, char *right, char c);//命令解析（命令 参数）
void str_upper(char *str);  //字符串转大写

#endif /* _STR_H_ */