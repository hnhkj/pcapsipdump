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

    Project's home: http://pcapsipdump.sf.net/
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "calltable.h"

#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))

#ifdef USE_CALLTABLE_CACHE
using namespace std;

bool operator <(addr_port const& a, addr_port const& b)
{
    return a.addr < b.addr || (a.addr == b.addr && a.port < b.port );
}
#endif

calltable::calltable()
{
    table.clear();
    erase_non_t38 = 0;
}

int calltable::add(
	char *call_id,
	unsigned long call_id_len,
        char *caller,
        char *callee,
	time_t time)
{
    int idx = -1;
    for (int i = 0; i < (int)table.size(); i++) {
	if (table[i].is_used == 0) {
	    idx = i;
	    break;
	}
    }
    if (idx == -1) {
	idx = table.size();
	table.push_back(calltable_element());
    }
    table[idx].is_used=1;
    table[idx].rtpmap_event = 101;
    table[idx].had_t38=0;
    table[idx].had_bye=0;
    memcpy(table[idx].call_id,call_id,MIN(call_id_len,32));
    table[idx].call_id_len=call_id_len;
    memcpy(table[idx].caller, caller, sizeof(table[0].caller));
    memcpy(table[idx].callee, callee, sizeof(table[0].callee));
    table[idx].ip_n=0;
    table[idx].f_pcap=NULL;
    table[idx].first_packet_time = time;
    table[idx].last_packet_time=time;
    global_last_packet_time=time;
#ifdef USE_CALLTABLE_CACHE
    {
        std::string s(call_id, call_id_len);
        call_id_cache[s] = idx;
    }
#endif
    return idx;
}

int calltable::find_by_call_id(
	char *call_id,
	unsigned long call_id_len)
{
#ifdef USE_CALLTABLE_CACHE
    std::string s(call_id, call_id_len);
    if (call_id_cache.count(s)){
        return call_id_cache[s];
    }else{
        return -1;
    }
#else
    int i;
    for (i = 0; i < (int)table.size(); i++) {
	if ((table[i].is_used!=0)&&
	    (table[i].call_id_len==call_id_len)&&
	    (memcmp(table[i].call_id,call_id,MIN(call_id_len,32))==0)){
	    return i;
	}
    }
    return -1;
#endif
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
#ifdef USE_CALLTABLE_CACHE
        cache[(struct addr_port){addr, port}] = (struct ileg_irtp_ssrc){call_idx, n, 0};
#endif
    }
    return 0;
}

//returns 1 if found or 0 if not found, and updates idx_leg and idx_rtp
int calltable::find_ip_port_ssrc(
            in_addr_t addr,
            unsigned short port,
            uint32_t ssrc,
            int *idx_leg,
            int *idx_rtp)
{
    int i_leg,i_rtp;

#ifdef USE_CALLTABLE_CACHE
    struct addr_port ap = {addr, port};
    while(true){
        if(this->cache.count(ap)){
            *idx_leg = cache[ap].ileg;
            *idx_rtp = cache[ap].irtp;
            if(*idx_leg >= 0){
                if(ssrc != cache[ap].ssrc){ // new ssid
                    if(table[*idx_leg].had_bye){ // and call has finished
                        // that's probably ip/port reuse
                        cache.erase(ap);
                        break; // abandon cache code, go to full search
                    }else{
                        //got new ssrc in the same ongoing call - update table & cache
                        table[*idx_leg].ssrc[*idx_rtp] = ssrc;
                        cache[ap] = (struct ileg_irtp_ssrc){*idx_leg, *idx_rtp, ssrc};
                    }
                }
                return 1;
            }else{
                return 0;
            }
        }
        break;
    }
#endif
    for (i_leg = 0; i_leg < (int)table.size(); i_leg++){
        for(i_rtp=0; i_rtp < MIN(calltable_max_ip_per_call, table[i_leg].ip_n); i_rtp++){
            if(table[i_leg].port[i_rtp] == port &&
               table[i_leg].ip  [i_rtp] == addr){
                if(!table[i_leg].had_bye || table[i_leg].ssrc[i_rtp]==ssrc){
#ifdef USE_CALLTABLE_CACHE
                    cache[ap] = (struct ileg_irtp_ssrc){i_leg, i_rtp, ssrc};
#endif
                    table[i_leg].ssrc[i_rtp]=ssrc;
                    *idx_leg=i_leg;
                    *idx_rtp=i_rtp;
                    return 1;
                }
            }
        }
    }
#ifdef USE_CALLTABLE_CACHE
    // add negative cache entry
    // TODO: how do we clean those up, to avoid memory leak?
    cache[ap] = (struct ileg_irtp_ssrc){-1, -1, 0};
#endif
    return 0;
}

int calltable::do_cleanup( time_t currtime ){
    int idx;
    for (idx = 0; idx < (int)table.size(); idx++) {
	if(table[idx].is_used && currtime-table[idx].last_packet_time > 300){
	    if (table[idx].f_pcap!=NULL){
		pcap_dump_close(table[idx].f_pcap);
                if (erase_non_t38 && !table[idx].had_t38) {
                    unlink(table[idx].fn_pcap);
                }
	    }
	    memset((void*)&table[idx],0,sizeof(table[idx]));
	    table[idx].is_used=0;
	    table[idx].ip_n=0;
#ifdef USE_CALLTABLE_CACHE
            for(int i_rtp=0; i_rtp<table[idx].ip_n; i_rtp++){
                struct addr_port ap = {table[idx].ip[i_rtp],
                                       table[idx].port[i_rtp]};
                cache.erase(ap);
            }
            {
                std::string s(table[idx].call_id, table[idx].call_id_len);
                call_id_cache.erase(s);
            }
#endif
	}
    }
    return 0;
}
