#include "privsock.h"
#include "sysutil.h"

void priv_sock_init(session_t *sess)
{
	int sockfds[2];
	if(socketpair(PF_UNIX, SOCK_STREAM, 0, sockfds) < 0)
		ERR_EXIT("socketpair");

	sess->child_fd = sockfds[1];
	sess->parent_fd = sockfds[0];
}

void priv_sock_close(session_t *sess)
{
	if(sess->parent_fd != -1)
	{
		close(sess->parent_fd);
		sess->parent_fd = -1;
	}
	if(sess->child_fd != -1)
	{
		close(sess->child_fd);
		sess->child_fd = -1;
	}
}

void priv_sock_set_parent_context(session_t *sess) //设置父进程上下文环境
{
	//对于父进程来说子进程的fd是用不上的（写时拷贝.....数据独有）
	if(sess->child_fd != -1)
	{
		close(sess->child_fd);
		sess->child_fd = -1;
	}
}

void priv_sock_set_child_context(session_t *sess)  //设置子进程上下文环境
{
	//同上
	if(sess->parent_fd != -1)
	{
		close(sess->parent_fd);
		sess->parent_fd = -1;
	}
}

void priv_sock_send_cmd(int fd, char cmd)
{
	int ret;
	ret = send(fd, &cmd, sizeof(cmd), 0);
	if(ret != sizeof(cmd))
		ERR_EXIT("priv_sock_send_cmd err.");
}

char priv_sock_get_cmd(int fd)
{
	char cmd;
	int ret;
	ret = recv(fd, &cmd, sizeof(cmd), 0);
	if(ret == 0)
	{
		printf("ftp process exit.\n");
		exit(EXIT_SUCCESS);
	}
	else if (ret != sizeof(cmd))
	{
		ERR_EXIT("priv_sock_get_cmd err.");
	}
	return cmd;
}

void priv_sock_send_result(int fd, char res)
{
	int ret;
	ret = send(fd, &res, sizeof(res), 0);
	if(ret != sizeof(res))
		ERR_EXIT("priv_sock_send_result err.");
}

char priv_sock_get_result(int fd)
{
	char res;
	int ret;
	ret = recv(fd, &res, sizeof(res), 0);
	if(ret == 0)
	{
		printf("ftp process exit.\n");
		exit(EXIT_SUCCESS);
	}
	else if (ret != sizeof(res))
	{
		ERR_EXIT("priv_sock_get_result err.");
	}
	return res;
}

void priv_sock_send_int(int fd, int the_int)
{
	int ret;
	ret = send(fd, &the_int, sizeof(the_int), 0);
	if(ret != sizeof(the_int))
		ERR_EXIT("priv_sock_send_int err.");
}

int priv_sock_get_int(int fd)
{
	int res;
	int ret;
	ret = recv(fd, &res, sizeof(res), 0);
	if(ret == 0)
	{
		printf("ftp process exit.\n");
		exit(EXIT_SUCCESS);
	}
	else if (ret != sizeof(res))
	{
		ERR_EXIT("priv_sock_get_int err.");
	}
	return res;
}

void priv_sock_send_buf(int fd, const char *buf, unsigned int len)
{
	priv_sock_send_int(fd, len);
	int ret;
	ret = send(fd, buf, len, 0);
	if(ret != len)
		ERR_EXIT("priv_sock_send_buf err.");
}

void priv_sock_recv_buf(int fd, char *buf, unsigned int len)   //len 有啥用？
{
	unsigned int recv_len = priv_sock_get_int(fd);
	int ret = recv(fd, buf, recv_len, 0);
	if(ret != recv_len)
		ERR_EXIT("priv_sock_recv_buf err.");
}

void priv_sock_send_fd(int sock_fd, int fd)
{
	send_fd(sock_fd, fd);
}

int priv_sock_recv_fd(int sock_fd)
{
	return recv_fd(sock_fd);
}