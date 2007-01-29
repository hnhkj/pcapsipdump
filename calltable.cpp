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
#include <time.h>
#include "calltable.h"

#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))

calltable::calltable()
{
    table_size=0;
    table=(calltable_element*)malloc(sizeof(calltable_element)*calltable_max);
}

int calltable::add(
	char *call_id,
	unsigned long call_id_len,
	time_t time)
{
    unsigned long idx,i,found_empty=0;
    for (i=0;i<table_size;i++){
	if(table[i].is_used==0){
	    idx=i;
	    found_empty=1;
	    break;
	}
    }
    if (!found_empty){
	idx=table_size;
	table_size++;
    }
    table[idx].is_used=1;
    memcpy(table[idx].call_id,call_id,MIN(call_id_len,32));
    table[idx].call_id_len=call_id_len;
    table[idx].ip_n=0;
    table[idx].last_packet_time=time;
    global_last_packet_time=time;
    return idx;
}

int calltable::find_by_call_id(
	char *call_id,
	unsigned long call_id_len)
{
    int i;
    for (i=0;i<(int)table_size;i++){
	if ((table[i].is_used!=0)&&
	    (table[i].call_id_len==call_id_len)&&
	    (memcmp(table[i].call_id,call_id,MIN(call_id_len,32))==0)){
	    return i;
	}
    }
    return -1;
}

int calltable::add_ip_port(
	    int call_idx,
	    in_addr_t addr,
	    unsigned short port)
{
    int i,found;
    int n=table[call_idx].ip_n;
    if (n>=calltable_max_ip_per_call){
	return -1;	
    }
    found=0;
    for(i=0;i<n;i++){
	if(table[call_idx].ip[i]==addr && 
	   table[call_idx].port[i]==port){
	    found=1;
	    break;
	} 
    }
    if(!found){
	table[call_idx].ip[n]=addr;
	table[call_idx].port[n]=port;
	table[call_idx].ip_n++;
    }
    return 0;
}

//returns idx or -1 if not found
int calltable::find_ip_port(
	    in_addr_t addr,
	    unsigned short port)
{
    int idx,i;
    for(idx=0;idx<(int)table_size;idx++){
	for(i=0;i<table[idx].ip_n;i++){
	    if(table[idx].port[i]==port && table[idx].ip[i]==addr){
		return idx;
	    }
	} 
    }
    return -1;
}

int calltable::do_cleanup( time_t currtime ){
    int idx;
    for(idx=0;idx<(int)table_size;idx++){
	if(table[idx].is_used && currtime-table[idx].last_packet_time > 300){
	    if (table[idx].f_pcap!=NULL){
		pcap_dump_close(table[idx].f_pcap);
	    }
	    if (table[idx].f!=NULL){
		fclose(table[idx].f);
	    }
	    memset((void*)&table[idx],0,sizeof(table[idx]));
	    table[idx].is_used=0;
	} 
    }
    return 0;
}
