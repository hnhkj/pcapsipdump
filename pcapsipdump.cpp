/*
    This file is part of pcapsipdump

    pcapsipdump is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    pcapsipdump is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Foobar; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

    ---

    You can send your updates, patches and suggestions on this software
    to it's original author, Andrew Chernyak (nording@yandex.ru)
    This would be appreciated, but not required.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>
#include <endian.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <net/ethernet.h>

#include <pcap.h>

#include "calltable.h"
#include "pcapsipdump.h"

#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))

int get_sip_peername(char *data, int data_len, char *tag, char *caller, int caller_len);
int get_ip_port_from_sdp(char *sdp_text, in_addr_t *addr, unsigned short *port);
char * gettag(const void *ptr, unsigned long len, const char *tag, unsigned long *gettaglen);

calltable *ct;

void sigint_handler(int param)
{
    printf("SIGINT received, terminating\n");
    ct->do_cleanup(0);
    exit(1);
}

int main(int argc, char *argv[])
{

    pcap_t *handle;/* Session handle */
    char *opt_chdir;/* directory to write dump */
    char *ifname;/* interface to sniff on */
    char *fname;/* pcap file to read on */
    char errbuf[PCAP_ERRBUF_SIZE];/* Error string */
    struct bpf_program fp;/* The compiled filter */
    char filter_exp[] = "udp";/* The filter expression */
    bpf_u_int32 mask;/* Our netmask */
    bpf_u_int32 net;/* Our IP */
    struct pcap_pkthdr header;/* The header that pcap gives us */
    const u_char *packet;/* The actual packet */
    unsigned long last_cleanup=0;
    int opt_fork=1;
    int opt_promisc=1;

    ifname=NULL;
    fname=NULL;
    opt_chdir="/var/spool/pcapsipdump";
    while(1) {
        char c;
        c = getopt_long (argc, argv, "i:r:d:fp",
                        NULL, NULL);
        if (c == -1)
            break;

        switch (c) {
            case 'i':
                ifname=optarg;
                break;
            case 'r':
                fname=optarg;
                break;
            case 'd':
                opt_chdir=optarg;
                break;
            case 'f':
                opt_fork=0;
                break;
            case 'p':
                opt_promisc=0;
                break;
        }
    }
    
    // allow interface to be specified without '-i' option - for sake of compatibility
    if (optind < argc) {
	ifname = argv[optind];
    }

    if ((fname==NULL)&&(ifname==NULL)){
	printf("pcapsipdump version %s\n"
	       "Usage: pcapsipdump [-fp] [-i <interface>] [-r <file>] [-d <working directory>]\n"
	       " -f     Do not fork or detach from controlling terminal.\n"
	       " -p     Do not put the interface into promiscuous mode.\n",PCAPSIPDUMP_VERSION);
	return 1;
    }

    ct = new calltable;
    signal(SIGINT,sigint_handler);

    if (ifname){
	printf("Capturing on interface: %s\n", ifname);
	/* Find the properties for interface */
	if (pcap_lookupnet(ifname, &net, &mask, errbuf) == -1) {
	    fprintf(stderr, "Couldn't get netmask for interface %s: %s\n", ifname, errbuf);
	    net = 0;
	    mask = 0;
	}
	handle = pcap_open_live(ifname, 1600, opt_promisc, 1000, errbuf);
	if (handle == NULL) {
	    fprintf(stderr, "Couldn't open inteface '%s': %s\n", ifname, errbuf);
	    return(2);
	}
    }else{
	printf("Reading file: %s\n", fname);
        net = 0;
        mask = 0;
	handle = pcap_open_offline(fname, errbuf);
	if (handle == NULL) {
	    fprintf(stderr, "Couldn't open pcap file '%s': %s\n", ifname, errbuf);
	    return(2);
	}
    }

    chdir(opt_chdir);

    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
	return(2);
    }

    if (opt_fork){
	// daemonize
	if (fork()) exit(0);
    }

    while ((packet = pcap_next(handle, &header))){
	{
	    struct iphdr *header_ip;
	    struct udphdr *header_udp;
	    char *data;
	    char *s;
	    char str1[1024],str2[1024];
	    unsigned long datalen;
	    unsigned long l;
	    int idx;

	    if (header.ts.tv_sec-last_cleanup>15){
		if (last_cleanup>=0){
		    ct->do_cleanup(header.ts.tv_sec);
		}
		last_cleanup=header.ts.tv_sec;
	    }

	    header_ip=(iphdr *)((uint32_t)packet+sizeof(struct ether_header));
	    if (header_ip->protocol==17){//UPPROTO_UDP=17
		header_udp=(udphdr *)((uint32_t)header_ip+sizeof(*header_ip));
		data=(char *)header_udp+sizeof(*header_udp);
		datalen=header.len-((unsigned long)data-(unsigned long)packet);

		if ((idx=ct->find_ip_port(header_ip->daddr,htons(header_udp->dest)))>=0){
		    if (ct->table[idx].f_pcap!=NULL){
			ct->table[idx].last_packet_time=header.ts.tv_sec;
			pcap_dump((u_char *)ct->table[idx].f_pcap,&header,packet);
		    }
		}else if (htons(header_udp->source)==5060||
		    htons(header_udp->dest)==5060){
		    data[datalen]=0;
		    s=gettag(data,datalen,"Call-ID: ",&l);
		    if ((idx=ct->find_by_call_id(s,l))<0){
			if ((idx=ct->add(s,l,header.ts.tv_sec))<0){
			    printf("Too many simultanious calls. runt out of call table space!\n");
			}else{
			    char sip_method[256];
			    //figure out method
			    memcpy(sip_method,data,sizeof(sip_method)-1);
			    sip_method[sizeof(sip_method)-1]=' ';
			    if (strchr(sip_method,' ')!=NULL){
				*strchr(sip_method,' ')='\0';
			    }else{
				sip_method[0]='\0';
			    }
			    if (strcmp(sip_method,"INVITE")==0){
				struct tm *t;
				char caller[256];
				char called[256];
				t=localtime(&header.ts.tv_sec);
				get_sip_peername(data,datalen,"From: ",caller,sizeof(caller));
				get_sip_peername(data,datalen,"To: ",called,sizeof(called));
				sprintf(str2,"%04d%02d%02d",
					t->tm_year+1900,t->tm_mon+1,t->tm_mday);
				mkdir(str2,0700);
				sprintf(str2,"%04d%02d%02d/%02d",
					t->tm_year+1900,t->tm_mon+1,t->tm_mday,t->tm_hour);
				mkdir(str2,0700);
				sprintf(str2,"%04d%02d%02d/%02d/%04d%02d%02d-%02d%02d%02d-%s-%s",
					t->tm_year+1900,t->tm_mon+1,t->tm_mday,t->tm_hour,
					t->tm_year+1900,t->tm_mon+1,t->tm_mday,t->tm_hour,t->tm_min,t->tm_sec,caller,called);
				memcpy(str1,s,l);
				str1[l]='\0';
				strcat(str2,"-");
				strcat(str2,str1);
				strcat(str2,".raw");
				ct->table[idx].f=NULL;
				str1[l]='\0';
				*strstr(str2,".raw")='\0';
				strcat(str2,".pcap");
				ct->table[idx].f_pcap=pcap_dump_open(handle,str2);
			    }else{
				ct->table[idx].f=NULL;
				ct->table[idx].f_pcap=NULL;
			    }
			}
		    }

		    s=gettag(data,datalen,"Content-Type: ",&l);
		    if(l>0 && memcmp(s,"application/sdp",l)==0 && strstr(data,"\r\n\r\n")!=NULL){
			in_addr_t tmp_addr;
			unsigned short tmp_port;
			if (!get_ip_port_from_sdp(strstr(data,"\r\n\r\n")+1,&tmp_addr,&tmp_port)){
			    ct->add_ip_port(idx,tmp_addr,tmp_port);
			}
		    }else{
		    }

		    if (ct->table[idx].f_pcap!=NULL){
			pcap_dump((u_char *)ct->table[idx].f_pcap,&header,packet);
		    }
		}

	    }
	}
    }
    /* And close the session */
    pcap_close(handle);
    return(0);
}

int get_sip_peername(char *data, int data_len, char *tag, char *peername, int peername_len){
    unsigned long r,r2,peername_tag_len;
    char *peername_tag=gettag(data,data_len,tag,&peername_tag_len);
    if ((r=(unsigned long)memmem(peername_tag,peername_tag_len,"sip:",4))==0){
	goto fail_exit;
    }
    r+=4;
    if ((r2=(unsigned long)memmem(peername_tag,peername_tag_len,"@",1))==0){
	goto fail_exit;
    }
    if (r2<=r){
	goto fail_exit;
    }
    memcpy(peername,(void*)r,r2-r);
    memset(peername+(r2-r),0,1);
    return 0;
fail_exit:
    strcpy(peername,"???");
    return 1;
}

int get_ip_port_from_sdp(char *sdp_text, in_addr_t *addr, unsigned short *port){
    unsigned long l;
    char *s;
    char s1[20];
    s=gettag(sdp_text,strlen(sdp_text),"c=IN IP4 ",&l);
    memset(s1,'\0',sizeof(s1));
    memcpy(s1,s,MIN(l,19));
    if ((long)(*addr=inet_addr(s1))==-1){
	*addr=0;
	*port=0;
	return 1;
    }
    s=gettag(sdp_text,strlen(sdp_text),"m=audio ",&l);
    if (l==0 || (*port=atoi(s))==0){
	*port=0;
	return 1;
    }
    return 0;
}

char * gettag(const void *ptr, unsigned long len, const char *tag, unsigned long *gettaglen){
    unsigned long register r,l,tl;

    tl=strlen(tag);
    r=(unsigned long)memmem(ptr,len,tag,tl);
    if(r==0){
	*gettaglen=0;	
    }else{
	r+=tl;
	l=(unsigned long)memmem((void *)r,len-(r-(unsigned long)ptr),"\r\n",2);
	if (l>0){
	    *gettaglen=l-r;
	}else{
	    *gettaglen=0;
	}
    }
    return (char*)r;
}
