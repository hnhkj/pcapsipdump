/*
    This file is part of pcapsipdump

    This file is based on linux kernel, namely:
    - udp.h by Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
    - ip.h by Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>

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

#define PCAPSIPDUMP_VERSION "0.1.3"

struct iphdr {
#if defined(__LITTLE_ENDIAN)
	uint8_t	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN)
	uint8_t	version:4,
  		ihl:4;
#elif
#error Endian not defined
#endif
	uint8_t	tos;
	uint16_t	tot_len;
	uint16_t	id;
	uint16_t	frag_off;
	uint8_t	ttl;
	uint8_t	protocol;
	uint16_t	check;
	uint32_t	saddr;
	uint32_t	daddr;
	/*The options start here. */
};


struct udphdr {
	uint16_t	source;
	uint16_t	dest;
	uint16_t	len;
	uint16_t	check;
};
