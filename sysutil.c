#include "sysutil.h"

void getlocalip(char *ip)
{
	char host[MAX_HOST_NAME_SIZE] = {0};
	if(gethostname(host, sizeof(host)) < 0)  //man
		ERR_EXIT("gethostname");
	//printf("host name = %s\n", host);
	
	struct hostent *ph;
	if((ph = gethostbyname(host)) == NULL)  //地址将存储在ph结构体中
		ERR_EXIT("gethostbyname");

	strcpy(ip, inet_ntoa(*(struct in_addr*)ph->h_addr));
}

int tcp_server(const char* host, unsigned short port)
{
	int listenfd;
	if((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)		
		ERR_EXIT("tcp_server");

	struct sockaddr_in addrSer;
	addrSer.sin_family = AF_INET;
	addrSer.sin_port = htons(port);
	addrSer.sin_addr.s_addr = inet_addr(host);
    
	int on = 1; //避免发生错误，在绑定之前将本地地址与端口设置为可重用
	if(setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)  
		ERR_EXIT("setsockopt");

	if((bind(listenfd, (struct sockaddr*)&addrSer, sizeof(addrSer))) <0)
		ERR_EXIT("bind741");

	if((listen(listenfd, SOMAXCONN)) < 0)
		ERR_EXIT("listen");

	return listenfd;
}

int tcp_client(int port)
{
	int sock;
	if((sock = socket(AF_INET, SOCK_STREAM, 0)) <0)
		ERR_EXIT("tcp_client:socket");
	
	if(port > 0)
	{
		int on = 1;
		if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)  
			ERR_EXIT("setsockopt");

		struct sockaddr_in address;
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = INADDR_ANY;
		address.sin_port = htons(port);
		if(bind(sock, (struct sockaddr*)&address, sizeof(struct sockaddr)) < 0)
			ERR_EXIT("bind 20");
	}
	return sock;
}

const char* statbuf_get_perms(struct stat* sbuf)
{
	static char perms[] = "----------";
	mode_t mode = sbuf->st_mode;
	switch(mode & S_IFMT)
	{
     case S_IFSOCK:
		 perms[0] = 's';  //socket文件
	     break;
	 case S_IFLNK:
		 perms[0] = 'l';  //链接文件
	     break;
	 case S_IFREG:    
		 perms[0] = '-';  //普通文件
	     break;
	 case S_IFBLK:    
		 perms[0] = 'b';  //块文件
	     break;
	 case S_IFDIR:    
		 perms[0] = 'd';  //目录文件
	     break;  
	 case S_IFCHR :    
		 perms[0] = 'c';  //字符文件
	     break;
	 case S_IFIFO :    
		 perms[0] = 'p';  //管道文件
	     break; 
	}

	//所属用户
	if(mode & S_IRUSR)
		perms[1] = 'r';
	if(mode & S_IWUSR)
		perms[2] = 'w';
	if(mode & S_IXUSR)
		perms[3] = 'x';

    //所属组
    if(mode & S_IRGRP)
		perms[4] = 'r';
	if(mode & S_IWGRP)
		perms[5] = 'w';
	if(mode & S_IXGRP)
		perms[6] = 'x';

    //其他用户
	if(mode & S_IROTH)
		perms[7] = 'r';
	if(mode & S_IWOTH)
		perms[8] = 'w';
	if(mode & S_IXOTH)
		perms[9] = 'x';

	return perms;
}

const char* statbuf_get_date(struct stat* sbuf)
{
	static char datebuf[64] = {0};
	time_t file_time = sbuf->st_mtime; //最后修改时间
    
	struct tm *ptm = localtime(&file_time);
	strftime(datebuf, 64, "%b %e %H:%m", ptm);

	return datebuf;
}

void send_fd(int sock_fd, int fd)
{
	int ret;
	struct msghdr msg;
	struct cmsghdr *p_cmsg;
	struct iovec vec;
	char cmsgbuf[CMSG_SPACE(sizeof(fd))];
	int *p_fds;
	char sendchar = 0;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	p_cmsg = CMSG_FIRSTHDR(&msg);
	p_cmsg->cmsg_level = SOL_SOCKET;
	p_cmsg->cmsg_type = SCM_RIGHTS;
	p_cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	p_fds = (int*)CMSG_DATA(p_cmsg);
	*p_fds = fd;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	vec.iov_base = &sendchar;
	vec.iov_len = sizeof(sendchar);
	ret = sendmsg(sock_fd, &msg, 0);
	if (ret != 1)
		ERR_EXIT("sendmsg");
}

int recv_fd(const int sock_fd)
{
	int ret;
	struct msghdr msg;
	char recvchar;
	struct iovec vec;
	int recv_fd;
	char cmsgbuf[CMSG_SPACE(sizeof(recv_fd))];
	struct cmsghdr *p_cmsg;
	int *p_fd;
	vec.iov_base = &recvchar;
	vec.iov_len = sizeof(recvchar);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	msg.msg_flags = 0;

	p_fd = (int*)CMSG_DATA(CMSG_FIRSTHDR(&msg));
	*p_fd = -1;  
	ret = recvmsg(sock_fd, &msg, 0);
	if (ret != 1)
		ERR_EXIT("recvmsg");

	p_cmsg = CMSG_FIRSTHDR(&msg);
	if (p_cmsg == NULL)
		ERR_EXIT("no passed fd");


	p_fd = (int*)CMSG_DATA(p_cmsg);
	recv_fd = *p_fd;
	if (recv_fd == -1)
		ERR_EXIT("no passed fd");

	return recv_fd;
}

//获取秒
static struct timeval s_cur_time;
long get_time_sec()
{
	if(gettimeofday(&s_cur_time, NULL) < 0)  //NULL表示使用当前时区
		ERR_EXIT("gettimeofday");
	return s_cur_time.tv_sec;
}
//获取微秒
long get_time_usec()
{
	return s_cur_time.tv_usec;
}

//睡眠
void nano_sleep(double sleep_time)
{
	time_t sec =  (time_t)sleep_time;  //sec是slee_time的整数部分
	double decimal = sleep_time - (double)sec; //相减得到小数部分

	struct timespec ts;
	ts.tv_sec = sec;
	ts.tv_nsec = (long)(decimal * 1000000000); 

	int ret;
	do
	{
		ret = nanosleep(&ts, &ts); //纳秒级别休眠 //被信号中断时返回-1
	}while(ret==-1 && errno==EINTR);  //循环用于预防休眠被信号中断  
}