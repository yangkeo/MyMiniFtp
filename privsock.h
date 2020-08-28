#ifndef _PRIVSOCK_H_
#define _PRIVSOCK_H_

#include "common.h"
#include "session.h"

//FTP���������nobody�������������
#define PRIV_SOCK_GET_DATA_SOCK 1  //��ȡ���������׽���
#define PRIV_SOCK_PASV_ACTIVE 2    //��ȡ���������Ƿ񱻼���
#define PRIV_SOCK_PASV_LISTEN 3    //��ȡ�������ӵļ����׽���
#define PRIV_SOCK_PASV_ACCEPT 4    //��ȡ�������ӵĽ����׽���

//nobody ���̶�FTP������̵�Ӧ��
#define PRIV_SOCK_RESULT_OK 1      //����ok
#define PRIV_SOCK_RESULT_BAD 2     //����bad

void priv_sock_init(session_t *sess);
void priv_sock_close(session_t *sess);
void priv_sock_set_parent_context(session_t *sess); //���ø����������Ļ���
void priv_sock_set_child_context(session_t *sess);  //�����ӽ��������Ļ���
void priv_sock_send_cmd(int fd, char cmd);          
char priv_sock_get_cmd(int fd);
void priv_sock_send_result(int fd, char res);
char priv_sock_get_result(int fd);
void priv_sock_send_int(int fd, int the_int);
int priv_sock_get_int(int fd);
void priv_sock_send_buf(int fd, const char *buf, unsigned int len);
void priv_sock_recv_buf(int fd, char *buf, unsigned int len);
void priv_sock_send_fd(int sock_fd, int fd);
int priv_sock_recv_fd(int sock_fd);

#endif