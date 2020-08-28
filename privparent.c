#include "privparent.h"
#include "session.h"
#include "privsock.h"

static void privop_pasv_get_data_sock(session_t *sess); //获取主动模式数据连接套接字
static void privop_pasv_active(session_t *sess);        //判断是否处于被动模式的激活状态
static void privop_pasv_listen(session_t *sess);        //获取被动模式下的监听端口
static void privop_pasv_accept(session_t *sess);        //获取被动模式下的数据连接套接字

int capset(cap_user_header_t hdrp, const cap_user_data_t datap)
{
	return syscall(__NR_capset, hdrp, datap);
}

static void minimize_privilege()
{
	/*
	 #define _LINUX_CAPABILITY_VERSION_1  0x19980330
     #define _LINUX_CAPABILITY_U32S_1     1

     #define _LINUX_CAPABILITY_VERSION_2  0x20071026
     #define _LINUX_CAPABILITY_U32S_2     2
	typedef struct __user_cap_header_struct 
	{
        __u32 version;
        int pid;
    } *cap_user_header_t;

    typedef struct __user_cap_data_struct 
    {
       __u32 effective;
       __u32 permitted;
       __u32 inheritable;
    } *cap_user_data_t;*/

	 //int capset(cap_user_header_t hdrp, const cap_user_data_t datap);
	 //设置线程特殊能力
	struct __user_cap_header_struct cap_header;
	struct __user_cap_data_struct  cap_data;
	memset(&cap_header, 0, sizeof(cap_header));
	memset(&cap_data, 0, sizeof(cap_data));

	cap_header.version = _LINUX_CAPABILITY_VERSION_2;
	cap_header.pid = 0;  //代表root进程，使nobody进程有root进程的部分权限
	
	int cap_mask;
	cap_mask |= (1 << CAP_NET_BIND_SERVICE);  //有了绑定小于1024端口的能力
	//允许有效的权限是谁，允许权限是什么权限  man capabilities
	cap_data.effective = cap_data.permitted = cap_mask;
	cap_data.inheritable = 0;  //不继承

	capset(&cap_header, &cap_data);
}

//nobody 进程
void handle_parent(session_t *sess)
{
	//将root进程更名为nobody进程
	struct passwd* pw = getpwnam("nobody");
	if(pw == NULL)
		ERR_EXIT("getpwnam");
	if(setegid(pw->pw_gid) < 0)
		ERR_EXIT("setegid");
	if(seteuid(pw->pw_uid) < 0)
		ERR_EXIT("seteuid");

	minimize_privilege();

	char cmd;
    while(1)
	{
		//不停等待ftp
		cmd = priv_sock_get_cmd(sess->parent_fd);
		switch(cmd)
		{
		case PRIV_SOCK_GET_DATA_SOCK: //获取数据连接套接字
			privop_pasv_get_data_sock(sess);
			break;
		case PRIV_SOCK_PASV_ACTIVE:    //获取被动连接是否被激活
			privop_pasv_active(sess);
			break;
		case PRIV_SOCK_PASV_LISTEN:    //获取被动连接的监听套接字
			privop_pasv_listen(sess); 
			break;
		case PRIV_SOCK_PASV_ACCEPT:    //获取被动连接的接受套接字
			privop_pasv_accept(sess); 
			break;
		}
	}
}

static void privop_pasv_get_data_sock(session_t *sess)
{
	unsigned short port = (unsigned short)priv_sock_get_int(sess->parent_fd);
	char ip[16] = {0};
	priv_sock_recv_buf(sess->parent_fd, ip, sizeof(ip));

	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	address.sin_addr.s_addr = inet_addr(ip);

	int fd = tcp_client(20);
	if(fd < 0)
	{
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}
	if(connect(fd, (struct sockaddr*)&address, sizeof(struct sockaddr)) < 0)
	{
		close(fd);
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;		
	}

	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	priv_sock_send_fd(sess->parent_fd, fd);
	close(fd);    //父（nobody）进程中一定要关闭，否则ftp进程连接不上!
}

static void privop_pasv_active(session_t *sess) 
{
	int active;
	if(sess->pasv_listen_fd != -1)
		active = 1;
	else
		active = 0;
	priv_sock_send_int(sess->parent_fd, active);
}

static void privop_pasv_listen(session_t *sess)
{
	//char *ip = "192.168.162.128";
	char ip[16] = {0};
	getlocalip(ip);
	sess->pasv_listen_fd = tcp_server(ip, 0); //o端口是系统自动随机分配端口  

	struct sockaddr_in address;
	socklen_t addrlen = sizeof(struct sockaddr);
	if(getsockname(sess->pasv_listen_fd, (struct sockaddr*)&address, &addrlen) < 0)
		ERR_EXIT("getsockname");
	
	unsigned short port = ntohs(address.sin_port);
	priv_sock_send_int(sess->parent_fd, (int)port);
}

static void privop_pasv_accept(session_t *sess) 
{
	int fd = accept(sess->pasv_listen_fd, NULL, NULL);
	close(sess->pasv_listen_fd);
	if(fd == -1)
	{
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}
	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	priv_sock_send_fd(sess->parent_fd, fd);
	close(fd);   //父（nobody）进程中一定要关闭，否则ftp进程连接不上!
}