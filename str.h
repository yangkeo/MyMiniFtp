#ifndef _STR_H_
#define _STR_H_

#include "common.h"

void str_trim_crlf(char *str); //�ü���ftpЭ�������ʽ�е�\n\r
void str_split(const char *str, char *left, char *right, char c);//������������� ������
void str_upper(char *str);  //�ַ���ת��д

#endif /* _STR_H_ */