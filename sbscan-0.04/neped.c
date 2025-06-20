
/* -----------------------------------------
     Network Promiscuous Ethernet Detector.
      Linux 2.0.x / 2.1.x, libc5 & GlibC
   -----------------------------------------
         (c) 1998 savage@apostols.org
   -----------------------------------------
   Scan your subnet, and detect promiscuous
   linuxes. It really works, not a joke.
   ----------------------------------------- */
   
/*
 * $Id: neped.c,v 1.4 1998/07/20 22:31:52 savage Exp $
 */
 
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <malloc.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <time.h>

#define ETH_P_ARP 	0x0806 
#define MAX_PACK_LEN 	2000
#define ETHER_HEADER_LEN 14
#define ARPREQUEST 	1
#define ARPREPLY 	2
#define perr(s) fprintf(stderr,s)

struct arp_struct
  {
    u_char  dst_mac[6];
    u_char  src_mac[6]; 
    u_short pkt_type;
    u_short hw_type;
    u_short pro_type;
    u_char  hw_len;
    u_char  pro_len;
    u_short arp_op;
    u_char  sender_eth[6];
    u_char  sender_ip[4];
    u_char  target_eth[6];
    u_char  target_ip[4];
  };

union
  {
    u_char full_packet[MAX_PACK_LEN];
    struct arp_struct arp_pkt;
  }
a;

#define full_packet a.full_packet
#define arp_pkt a.arp_pkt

char * 
inetaddr ( u_int32_t ip ) 
{
  struct in_addr in;
  in.s_addr = ip;
  return inet_ntoa(in);
}

char *
hwaddr (u_char * s)
{
  static char buf[30];
  sprintf (buf, "%02X:%02X:%02X:%02X:%02X:%02X", s[0], s[1], s[2], s[3], s[4], s[5]);
  return buf;
}

void
main (int argc, char **argv)
{
  int rec;
  int len, from_len, rsflags;
  struct ifreq if_data;
  struct sockaddr from;
  u_int8_t myMAC[6];
  u_int32_t myIP, myNETMASK, myBROADCAST, ip, dip, sip;

  if (getuid () != 0)
    {
      perr ("You must be root to run this program!\n");
      exit (0);
    }

  if (argc != 2)
    {
      fprintf(stderr,"Usage: %s eth0\n", argv[0]);
      exit (0);
    }

  if ((rec = socket (AF_INET, SOCK_PACKET, htons (ETH_P_ARP))) < 0)
    {
      perror("socket");
      exit (0);
    }

  printf ("----------------------------------------------------------\n");
  strcpy (if_data.ifr_name, argv[1]);
  if (ioctl (rec, SIOCGIFHWADDR, &if_data) < 0) {
    perr ("can't get HW addres of my interface!\n");
    exit(1);
  }
  memcpy (myMAC, if_data.ifr_hwaddr.sa_data, 6);
  printf ("> My HW Addr: %s\n", hwaddr (myMAC));

  if (ioctl (rec, SIOCGIFADDR, &if_data) < 0) {
    perr ("can't get IP addres of my interface!\n");
    exit(1);
  }
  memcpy ((void *) &ip, (void *) &if_data.ifr_addr.sa_data + 2, 4);
  myIP = ntohl (ip);
  printf ("> My IP Addr: %s\n", inetaddr(ip));

  if (ioctl (rec, SIOCGIFNETMASK, &if_data) < 0)
    perr ("can't get NETMASK addres of my interface!\n");
  memcpy ((void *) &ip, (void *) &if_data.ifr_netmask.sa_data + 2, 4);
  myNETMASK = ntohl (ip);
  printf ("> My NETMASK: %s\n", inetaddr(ip));

  if (ioctl (rec, SIOCGIFBRDADDR, &if_data) < 0)
    perr ("can't get BROADCAST addres of my interface!\n");
  memcpy ((void *) &ip, (void *) &if_data.ifr_broadaddr.sa_data + 2, 4);
  myBROADCAST = ntohl (ip);
  printf ("> My BROADCAST: %s\n", inetaddr(ip));

  if ((rsflags = fcntl (rec, F_GETFL)) == -1)
    {
      perror ("fcntl F_GETFL");
      exit (1);
    }

  if (fcntl (rec, F_SETFL, rsflags | O_NONBLOCK) == -1)
    {
      perror ("fcntl F_SETFL");
      exit (1);
    }

  
  printf ("----------------------------------------------------------\n");
  printf ("> Scanning ....\n");
  for (dip = (myIP & myNETMASK) + 1; dip < myBROADCAST; dip++)
    {
      bzero(full_packet, MAX_PACK_LEN);

      memcpy (arp_pkt.dst_mac, "\0\6\146\3\23\67", 6); /* 00:06:66:03:13:37 :) */
      memcpy (arp_pkt.src_mac, myMAC, 6);
      arp_pkt.pkt_type = htons( ETH_P_ARP );
      arp_pkt.hw_type = htons( 0x0001 );
      arp_pkt.hw_len = 6;
      arp_pkt.pro_type = htons( 0x0800 );
      arp_pkt.pro_len = 4;
      arp_pkt.arp_op = htons (ARPREQUEST);
      memcpy (arp_pkt.sender_eth, myMAC, 6);
      ip = htonl (myIP);
      memcpy (arp_pkt.sender_ip, &ip, 4);
      memcpy (arp_pkt.target_eth, "\0\0\0\0\0\0", 6);
      ip = htonl (dip);
      memcpy (arp_pkt.target_ip, &ip, 4);

      strcpy(from.sa_data, argv[1]);
      from.sa_family = 1;
          
      if( sendto (rec, full_packet, sizeof (struct arp_struct), 0, &from, sizeof(from)) < 0)
	  perror ("sendto");

      usleep (50);		

      len = recvfrom (rec, full_packet, MAX_PACK_LEN, 0, &from, &from_len);
      if (len <= ETHER_HEADER_LEN)
	continue;

      memcpy (&ip, arp_pkt.target_ip, 4);
      memcpy (&sip, arp_pkt.sender_ip, 4);

      if (ntohs (arp_pkt.arp_op) == ARPREPLY
	  && ntohl (ip) == myIP
	  && ( dip - ntohl(sip) >= 0 )
	  && ( dip - ntohl(sip) <= 2 ) )
	{
	  printf ("*> Host %s, %s **** Promiscuous mode detected !!!\n",
		  inetaddr (sip),
		  hwaddr (arp_pkt.sender_eth));
	}

    }

  printf ("> End.\n");

  exit (0);
}

