#include"ftpproto.h"
#include"ftpcodes.h"
#include"str.h"
#include "sysutil.h"
#include "privsock.h"
#include "tunable.h"

session_t *p_sess; //��miniftp��������

void ftp_reply(session_t *sess, int code, const char *text)
{
	char buf[MAX_BUFFER_SIZE] = {0};
	sprintf(buf, "%d %s\r\n", code, text);
	send(sess->ctrl_fd, buf, strlen(buf), 0);
}

/**************************����ӳ�����**********************************/

static void do_user(session_t *sess);
static void do_pass(session_t *sess);
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_pwd(session_t *sess);
static void do_type(session_t *sess);
static void do_port(session_t *sess);
static void do_list(session_t *sess);
static void do_pasv(session_t *sess);
static void do_cwd(session_t *sess);
static void do_mkd(session_t *sess);
static void do_rmd(session_t *sess);
static void do_rnfr(session_t *sess);
static void do_rnto(session_t *sess);
static void do_size(session_t *sess);
static void do_dele(session_t *sess);
static void do_stor(session_t *sess);
static void do_retr(session_t *sess);
static void do_rest(session_t *sess);
static void do_quit(session_t *sess);

typedef struct ftpcmd
{
	const char *cmd;
	void(*cmd_handler)(session_t *sess);
}ftpcmd_t;

//����ӳ���
static ftpcmd_t ctrl_cmds[] = 
{
	{"USER",  do_user},
	{"PASS",  do_pass},
	{"SYST",  do_syst},
	{"FEAT",  do_feat},
	{"PWD",   do_pwd},
	{"TYPE",  do_type},
	{"PORT",  do_port},
	{"LIST",  do_list},
	{"PASV",  do_pasv},
	{"CWD",   do_cwd},
	{"MKD",   do_mkd},
	{"RMD",   do_rmd},
	{"RNFR",  do_rnfr},
	{"RNTO",  do_rnto},
	{"SIZE",  do_size},
	{"DELE",  do_dele},
	{"STOR",  do_stor},
	{"RETR",  do_retr},
	{"REST",  do_rest},
	{"QUIT",  do_quit}
};
/************************************���жϿ�***********************************/
//�������ӿ��жϿ�
void start_data_alarm();
void handle_ctrl_timeout(int sig)
{
	shutdown(p_sess->ctrl_fd, SHUT_RD);
	//421
	ftp_reply(p_sess, FTP_IDLE_TIMEOUT, "Timeout.");
	shutdown(p_sess->ctrl_fd, SHUT_WR);
	exit(EXIT_SUCCESS);
	//close(p_sess->ctrl_fd);
}
void start_cmdio_alarm()
{
	if(tunable_idle_session_timeout > 0)
	{
		signal(SIGALRM, handle_ctrl_timeout);
		alarm(tunable_idle_session_timeout); //��������
	}
}

//�������ӿ��жϿ�
void handle_data_timeout(int sig)
{
	if(!p_sess->data_process)
	{
		//421
		ftp_reply(p_sess, FTP_DATA_TIMEOUT, "Data timeout. Reconnect Sorry.");
		exit(EXIT_FAILURE);
	}
	p_sess->data_process = 0;
	start_data_alarm();
}
void start_data_alarm()
{
	if(tunable_data_connection_timeout > 0)
	{
		signal(SIGALRM, handle_data_timeout);  //��װ�����ź�
		alarm(tunable_data_connection_timeout);  //��������
	}
	else if(tunable_idle_session_timeout > 0)
		alarm(0);
}

/*************************************************************************/


//ftp �������
void handle_child(session_t *sess)
{
	ftp_reply(sess, FTP_GREET, "(bit65 miniftp 1.0 )");

	int ret;
	while(1)
	{
		//��ͣ�ĵȴ��ͻ��˵�������д���
		memset(sess->cmdline, 0, MAX_COMMAND_LINE);
		memset(sess->cmd, 0, MAX_COMMAND);
		memset(sess->arg, 0, MAX_ARG);

		start_cmdio_alarm();  //����������������

		ret = recv(sess->ctrl_fd, sess->cmdline, MAX_COMMAND_LINE, 0); //����������⣬������ʱ�䵽�ͻᴥ�������ź�
		if(ret == -1)
			ERR_EXIT("readline");
		else if(ret == 0)
			exit(EXIT_SUCCESS);

		str_trim_crlf(sess->cmdline);
		//printf("cmdline = %s\n", sess->cmdline);
		str_split(sess->cmdline, sess->cmd, sess->arg, ' ');
		//printf("cmd = %s\n", sess->cmd);
		//printf("arg = %s\n", sess->arg);

		int table_size = sizeof(ctrl_cmds) / sizeof(ftpcmd_t);
		int i;
		for(i=0; i<table_size; ++i)
		{
			if(strcmp(sess->cmd, ctrl_cmds[i].cmd) == 0)
			{
				if(ctrl_cmds[i].cmd_handler != NULL)
					ctrl_cmds[i].cmd_handler(sess);
				else
					ftp_reply(sess, FTP_COMMANDNOTIMPL, "Unimplement command.");
				break;
			}
		}

		if(i >= table_size)
			ftp_reply(sess, FTP_BADCMD, "Unknown command.");
	}
}

//USER abc
static void do_user(session_t *sess)
{
	struct passwd *pwd = getpwnam(sess->arg);
	if(pwd != NULL)
		sess->uid = pwd->pw_uid;

	ftp_reply(sess, FTP_GIVEPWORD, "Please specify the password.");
}

//PASS 123abc
static void do_pass(session_t *sess)
{
	//��Ȩ
	struct passwd *pwd = getpwuid(sess->uid);
	if(pwd == NULL)
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}
	
	struct spwd *spd = getspnam(pwd->pw_name);
	if(spd == NULL)
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	char *encry_pwd = crypt(sess->arg, spd->sp_pwdp);
	if(strcmp(encry_pwd, spd->sp_pwdp) != 0)
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}
	
	setegid(pwd->pw_gid);
	seteuid(pwd->pw_uid);
	chdir(pwd->pw_dir);

	ftp_reply(sess, FTP_LOGINOK, "Login successful.");
}

static void do_syst(session_t *sess)
{
	ftp_reply(sess, FTP_SYSTOK, "UNIX Type: L8");
}

static void do_feat(session_t *sess)
{
	send(sess->ctrl_fd, "211-Features:\r\n" ,strlen("211-Features:\r\n"), 0);
	send(sess->ctrl_fd, " EPRT\r\n", strlen(" EPRT\r\n"), 0);
	send(sess->ctrl_fd, " EPSV\r\n", strlen(" EPSV\r\n"), 0);
	send(sess->ctrl_fd, " MDTM\r\n", strlen(" MDTM\r\n"), 0);
	send(sess->ctrl_fd, " PASV\r\n", strlen(" PASV\r\n"), 0);
	send(sess->ctrl_fd, " REST STREAM\r\n", strlen(" REST STREAM\r\n"), 0);
	send(sess->ctrl_fd, " SIZE\r\n", strlen(" SIZE\r\n"), 0);
	send(sess->ctrl_fd, " TVFS\r\n", strlen(" TVFS\r\n"), 0);
	send(sess->ctrl_fd, " UTF8\r\n", strlen(" UTF8\r\n"), 0);
	send(sess->ctrl_fd, "211 End\r\n", strlen("211 End\r\n"), 0);
}

static void do_pwd(session_t *sess)
{
	char buffer[MAX_BUFFER_SIZE] = {0};
	getcwd(buffer, MAX_BUFFER_SIZE); //��ȡ��������Ŀ¼��Ϊ����vsftpd/pub
	char rep[MAX_BUFFER_SIZE] = {0};
	sprintf(rep, "\"%s\"", buffer);
	ftp_reply(sess, FTP_MKDIROK, rep);
}

static void do_type(session_t *sess)
{
	if(strcmp(sess->arg, "A") == 0)
	{
		sess->is_ascii = 1;
		ftp_reply(sess, FTP_TYPEOK, "Switching to ASCII mode.");
	}
	else if(strcmp(sess->arg, "I") == 0)
	{
		sess->is_ascii = 0;
		ftp_reply(sess, FTP_TYPEOK, "Switching to Binary mode.");
	}
	else
	{
		ftp_reply(sess, FTP_BADCMD, "Unrecognised TYPE command.");
	}
}

//����ģʽ�»�ȡ�ͻ��˵ĵ�ַ��˿�
static void do_port(session_t *sess)
{
	//  PORT 10,202,155,42,61,8
	unsigned int rec[6] = {0};
	sscanf(sess->arg, "%u,%u,%u,%u,%u,%u", &rec[0], &rec[1], &rec[2], &rec[3], &rec[4], &rec[5]);
	int i = 0;
	while(i < 6)
	{
		printf("%u ",rec[i]);
		++i;
	}
	printf("\n");
	sess->port_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
	unsigned char *p = (unsigned char *)&sess->port_addr->sin_port;
	p[0] = rec[4];
	p[1] = rec[5];

	p = (unsigned char *)&sess->port_addr->sin_addr;
	p[0] = rec[0];
	p[1] = rec[1];
	p[2] = rec[2];
	p[3] = rec[3];
	sess->port_addr->sin_family = AF_INET;
    ftp_reply(sess, FTP_PORTOK, "command successful. Consider using PASV.");
}

static void do_pasv(session_t *sess)
{
	/*// 227 Entering Passive Mode (192,168,162,128,140,176).
	char ip[16] = "192.168.162.128"; //��������IP
	sess->pasv_listen_fd = tcp_server(ip, 0);//portΪ0����������ʱ�˿ں�

	struct sockaddr_in address;
	socklen_t addrlen = sizeof(struct sockaddr);
	if(getsockname(sess->pasv_listen_fd, (struct sockaddr*)&address, &addrlen) < 0)
		ERR_EXIT("getsockname");

	unsigned short port = ntohs(address.sin_port);

	int v[4] = {0};
	sscanf(ip, "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]);
	char msg[MAX_BUFFER_SIZE] = {0};
	sprintf(msg, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).", v[0],v[1],v[2],v[3], port>>8, port&0x00ff);
	ftp_reply(sess, FTP_PASVOK, msg);
	*/

	//char ip[16] = "192.168.162.128"; //��������IP
	char ip[16] = {0};
	getlocalip(ip);
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);
	unsigned short port = (unsigned short)priv_sock_get_int(sess->child_fd);

	int v[4] = {0};
	sscanf(ip, "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]);
	char msg[MAX_BUFFER_SIZE] = {0};
	sprintf(msg, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).", v[0],v[1],v[2],v[3], port>>8, port&0x00ff);
	ftp_reply(sess, FTP_PASVOK, msg);

}

/*****************************��ʾ�б�***********************************/
int port_active(session_t *sess)
{
	if(sess->port_addr)
	{
		if(pasv_active(sess))
		{
			fprintf(stderr, "both port and pasv are active.");
			exit(EXIT_FAILURE);
		}
        return 1;
	}
	return 0;
}

int pasv_active(session_t *sess)
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);
	int active = priv_sock_get_int(sess->child_fd);

	if(active)
	{
		if(port_active(sess))
		{
			fprintf(stderr, "both port and pasv are active.");
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	return 0;//����ģʽδ����
}

int get_port_fd(session_t *sess)
{
	//ftp ������nobody����ͨѶ
	int ret = 0;
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_GET_DATA_SOCK);
	unsigned short port = ntohs(sess->port_addr->sin_port);  //��ȡ���Ķ˿��������ֽ����������䴫������ת��Ϊ�����ֽ���
	char *ip = inet_ntoa(sess->port_addr->sin_addr);
		
	//���Ͷ˿ں͵�ַ
	priv_sock_send_int(sess->child_fd, (int)port);     //  nobody���̺�ftp�����Ǹ��ӹ�ϵ�����ݶ���
	priv_sock_send_buf(sess->child_fd, ip, strlen(ip));//  �����Ҫ��ftp�����н��ܵ�sess->port_addr����nobody���̣�����û���������
	
	char res = priv_sock_get_result(sess->child_fd);
	if(res == PRIV_SOCK_RESULT_BAD)
	{
		ret = 0;
	}
	else if(res == PRIV_SOCK_RESULT_OK)
	{
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
		ret = 1;
	}
	return ret;
}

int get_pasv_fd(session_t *sess)
{
	int ret = 1;
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCEPT);
	char res = priv_sock_get_result(sess->child_fd);
	if(res == PRIV_SOCK_RESULT_BAD)
	{
		ret = 0;
	}
	else if(res == PRIV_SOCK_RESULT_OK)
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);

	return ret;
}

int get_transfer_fd(session_t *sess)
{
	if(!port_active(sess) && !pasv_active(sess))
	{
		ftp_reply(sess, FTP_BADSENDCONN,"Use PORT or PASV first.");
		return 0;
	}

	int ret = 1;

	//��������ʱ
	if(port_active(sess))
	{
		if(!get_port_fd(sess))
			ret = 0;
	}
    
	//��������ʱ
	if(pasv_active(sess))
	{
		/*int sockCli = accept(sess->pasv_listen_fd, NULL, NULL);
		if(sockCli < 0)
		{
			ret = 0;
		}
		else
		{
			close(sess->pasv_listen_fd);
			sess->pasv_listen_fd = -1;
			sess->data_fd = sockCli;
			ret = 1;
		}*/
		if(!get_pasv_fd(sess))
			ret = 0;		
	}
    //���ӳɹ����ͷŵ�ַ��˿�
	if(sess->port_addr)
	{
		free(sess->port_addr);
		sess->port_addr = NULL;
	}

	//�������ݿ��жϿ�������
	if(ret)
		start_data_alarm();

	return ret;
}

static void list_common(session_t *sess)
{
	DIR *dir = opendir("."); //�򿪵�ǰĿ¼
	if(dir == NULL)
		return;

	struct stat sbuf; //�����ļ�����
	struct dirent *dt;
	//���ζ�ȡ��ǰĿ¼�µ�����
	while((dt = readdir(dir)) != NULL)
	{
		if(lstat(dt->d_name, &sbuf) < 0)
			continue;
		if(dt->d_name[0] == '.')  //���˵������ļ�
			continue;

		//drwxr-xr-x    3 1000     1000           30 Sep 09  2019 Desktop
		char buf[MAX_BUFFER_SIZE] = {0};
		//1.���Ȩ��
		const char *perms = statbuf_get_perms(&sbuf);
		int offset = 0;
		offset += sprintf(buf, "%s", perms);
		offset += sprintf(buf + offset, "%3d %-8d %-8d %8lld ", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid, (long long)sbuf.st_size); //3��λ�ã����Ҷ���
		//2.���ʱ������
		const char* date = statbuf_get_date(&sbuf);
		offset += sprintf(buf + offset, "%s ", date);
		sprintf(buf + offset, "%s\r\n", dt->d_name);

        send(sess->data_fd, buf, strlen(buf), 0);
	}
}

static void do_list(session_t *sess)
{
	//1.������������  (�����뱻��)
	if(get_transfer_fd(sess) == 0)
		return; //����ʧ��
	//2.�ظ�150
	ftp_reply(sess, FTP_DATACONN,"Here comes the directory listing.");
	//3.����Ŀ¼
	list_common(sess);
	//4.�ر�����
    close(sess->data_fd);
	sess->data_fd = -1;
	//5.�ظ�226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}
/************************************************************************/

//cwd�ı乤��Ŀ¼
static void do_cwd(session_t *sess)
{
	if(chdir(sess->arg) < 0)
	{
		//550 Failed to change directory.
		ftp_reply(sess, FTP_NOPERM, "Failed to change directory.");
		return;
	}
	//250 Directory successfully changed.
	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

//����Ŀ¼
static void do_mkd(session_t *sess)
{
	if(mkdir(sess->arg, 0777) < 0)
	{
		//550 Create directory operation failed.
		ftp_reply(sess, FTP_NOPERM, "Create directory operation failed.");
		return;
	}
	//257 "/home/yangke/t1" created
	char buf[MAX_BUFFER_SIZE] = {0};
	sprintf(buf, "\"%s\" created", sess->arg);
	ftp_reply(sess, FTP_MKDIROK, buf);
}

//ɾ��Ŀ¼
static void do_rmd(session_t *sess)
{
	if(rmdir(sess->arg) < 0)
	{
		ftp_reply(sess,FTP_NOPERM, "Remove directory operation failed.");
		return;
	}
	// 250 Remove directory operation successful.
	ftp_reply(sess, FTP_RMDIROK, "Remove directory operation successful.");
}

//��ȡ��Ҫ�������ļ���·��
static void do_rnfr(session_t *sess)
{
	sess->rnfr_name = (char*)malloc(strlen(sess->arg) + 1);
	memset(sess->rnfr_name, 0, (strlen(sess->arg) + 1));
	strcpy(sess->rnfr_name, sess->arg);
	//350
	ftp_reply(sess, FTP_RNFROK, "Ready for RNTO.");
}

//�������ļ�
static void do_rnto(session_t *sess)
{
	if(sess->rnfr_name == NULL)
		ftp_reply(sess, FTP_NEEDRNFR, "RNFR required first.");
	if(rename(sess->rnfr_name, sess->arg) < 0)
	{
		ftp_reply(sess, FTP_NOPERM, "Rename failed.");
		return;
	}
	
	free(sess->rnfr_name);
	sess->rnfr_name = NULL;
	
	ftp_reply(sess, FTP_RENAMEOK, "Rename successful.");
}

//�ļ���С
static void do_size(session_t *sess)
{
	struct stat sbuf;
	if(stat(sess->arg, &sbuf) < 0)
	{
		//550 Could not get file size.
		ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
		return;
	}
	//S_ISREG  ȥman 2 stat
	if(!S_ISREG(sbuf.st_mode))
	{
		ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
		return;
	}

	char buf[MAX_BUFFER_SIZE] = {0};
	sprintf(buf, "%d", sbuf.st_size);
	ftp_reply(sess, FTP_SIZEOK, buf);  //213  size
}

//ɾ���ļ�
static void do_dele(session_t *sess)
{
	if(unlink(sess->arg) < 0)
	{
		ftp_reply(sess, FTP_NOPERM, "Delete operation failed.");
		return;
	}
	//250 Delete operation successful.
	ftp_reply(sess, FTP_DELEOK, "Delete operation successful.");
}

//���ٺ���
static void limit_rate(session_t *sess, int bytes_transfered, int isupload)
{
	//�ڴ˵Ǽ�ʱ��
	long cur_sec = get_time_sec(); 
	long cur_usec = get_time_usec();
	
	//����ȡ������ʱ��
	double pass_time = (double)(cur_sec - sess->transfer_start_sec);
	pass_time += (double)((cur_usec - sess->transfer_start_usec) / (double)1000000);

	//��ǰ�Ĵ����ٶ�
	unsigned int cur_rate = (unsigned int)((double)bytes_transfered / pass_time);

	double rate_ratio; //��ǰ��������/���������
	if(isupload)
	{
		if(cur_rate <= sess->upload_max_rate)
		{
			sess->transfer_start_sec = cur_sec;
			sess->transfer_start_usec = cur_usec;
			return;
		}
		//(ʱ��2 - ʱ��1) = (��ǰ��������/��������� - 1) * ��ǰ����ʱ��
		rate_ratio = cur_rate / sess->upload_max_rate;
	}
	else
	{
		if(cur_rate <= sess->download_max_rate)
		{
			sess->transfer_start_sec = cur_sec;
			sess->transfer_start_usec = cur_usec;
			return;
		}
		rate_ratio = cur_rate / sess->download_max_rate;
	}
	
	//(ʱ��2 - ʱ��1) = (��ǰ��������/��������� - 1) * ��ǰ����ʱ��
	double sleep_time = (rate_ratio - 1) * pass_time;
	nano_sleep(sleep_time);

	sess->transfer_start_sec = get_time_sec();
	sess->transfer_start_usec = get_time_usec();
}

//�ͻ����ļ��ϴ�
static void do_stor(session_t *sess)
{
	//1.������������
	if(get_transfer_fd(sess) == 0)
		return;
	int fd = open(sess->arg, O_CREAT|O_WRONLY, 0775); //�ڷ���������ͬ���ļ���׷��д
	if(fd == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}
	//150  Ok to send data.
	ftp_reply(sess, FTP_DATACONN, "Ok to send data.");
	
	//�ϵ�����
	long long offset = sess->restart_pos;
	sess->restart_pos = 0;
	if(lseek(fd, offset, SEEK_SET) <0)
	{
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}

	//�Ǽ�ʱ��
	sess->transfer_start_sec = get_time_sec(); 
	sess->transfer_start_usec = get_time_usec();

	//2.��ʼ���ܲ�д���ļ� 
	char buf[MAX_BUFFER_SIZE] = {0};
	int ret;
	while(1)
	{
		ret = recv(sess->data_fd, buf, MAX_BUFFER_SIZE, 0);
		if(ret == -1)
		{
			//451
			ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from local file.");
			break;
		}
		else if(ret == 0)
		{
			//�������
			//226 Transfer complete.
			ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
			break;
		}

		//���ÿ��жϿ�״̬
		sess->data_process = 1;

		//����
		if(sess->upload_max_rate != 0)
			limit_rate(sess, ret, 1);

		if(write(fd, buf, ret) != ret)
		{
			ftp_reply(sess, FTP_BADSENDFILE, "Failure writting from local file.");
			break;
		}
	}
	close(fd);
	close(sess->data_fd);
	sess->data_fd = -1;

	//��������������������
	start_cmdio_alarm();
}

//�ӷ����������ļ�
static void do_retr(session_t *sess)
{
	//1.������������
	if(get_transfer_fd(sess) == 0)
		return;

	int fd = open(sess->arg, O_RDONLY);  //ֻ����ʽ�򿪷������Ҫ���ص��ļ�
	if(fd == -1)
	{
		//550
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	struct stat sbuf;
	fstat(fd, &sbuf); //��ȡ��Ҫ���͵��ļ�����
	
	//�ϵ�����
	long long offset = sess->restart_pos;
	sess->restart_pos = 0;
	if(offset >= sbuf.st_size)
	{
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}
	else
	{
		char msg[MAX_BUFFER_SIZE] = {0};
		if(sess->is_ascii)
			sprintf(msg, "Opening ASCII mode data connection for %s (%lld bytes).", sess->arg, sbuf.st_size);
		else
			sprintf(msg, "Opening BINARY mode data connection for %s (%lld bytes).", sess->arg, sbuf.st_size);
		// 150 Opening ASCII mode data connection for /home/bss/mytt/abc/test.cpp (70 bytes).
		ftp_reply(sess, FTP_DATACONN, msg);
		
		if(lseek(fd, offset, SEEK_SET) < 0)
		{
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
			return;
		}

		char buf[MAX_BUFFER_SIZE] = {0};
		//��ʼ��������
		int read_total_bytes = (long long)sbuf.st_size - offset;  //��Ҫ�����ֽ������ܴ�С
		int read_count = 0;
		int ret;

		//�Ǽ�ʱ��
		sess->transfer_start_sec = get_time_sec(); 
		sess->transfer_start_usec = get_time_usec();
		while(1)
		{
			read_count = read_total_bytes > MAX_BUFFER_SIZE ? MAX_BUFFER_SIZE : read_total_bytes; 
			ret = read(fd, buf, read_count);
			if(ret == -1 || ret != read_count)
			{
				ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from local file.");
				break;
			}
			if(ret == 0)
			{
				// 226 Transfer complete.  ������� �˳�
				ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");  
				break;
			}

			//���ÿ��жϿ�״̬
			sess->data_process = 1;

			//����
			if(sess->download_max_rate != 0)
				limit_rate(sess, read_count, 0);

			if(send(sess->data_fd, buf, ret, 0) != ret)
			{
				ftp_reply(sess, FTP_BADSENDFILE, "Failure writting from local file.");
				break;
			}
			read_total_bytes -= read_count;
		}
	}
	
	close(fd);
	close(sess->data_fd);
	sess->data_fd = -1;

	//��������������������
	start_cmdio_alarm();
}

//�ϵ����� rest�����
static void do_rest(session_t *sess)
{
	sess->restart_pos = (long long)atoll(sess->arg);
	char msg[MAX_BUFFER_SIZE] = {0};
	sprintf(msg, "Restart position accepted (%lld).", sess->restart_pos);
	ftp_reply(sess, FTP_RESTOK, msg);
}

static void do_quit(session_t *sess)
{
	ftp_reply(sess, FTP_GOODBYE, "Goodbye.");
}