/*
 * Copyright 1999 by Ulrik De Bie. Subject to the GPL.
 * garp		Garp is a Gratuitous ARP implementation. Garp can be used to 
 *              automagically (and randomly) assign unused IP addresses (
 *              from a given IP range) to a network interface.
 *
 * Author:      Ulrik De Bie <ulrik@mind.be> with some little help from
 *              Dag Wieers <dag@mind.be>
 *
 *
*/

#define VERSION "0.7.2"

#include <strings.h>
#include <memory.h>
#include <malloc.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <limits.h>

#define EXTRACT_16BITS(p) \
        ((u_short)ntohs(*(u_short *)(p)))
#define EXTRACT_32BITS(p) \
        ((u_int32_t)ntohl(*(u_int32_t *)(p)))

struct add_mask_t {
    struct in_addr address, netmask;
    unsigned int prefix;
};
const char *program = NULL;
int verbose = 0;
int quiet = 0;
enum arp_check_reply {
    IGNORE_PACKET, ANSWERRED_MYSELF, ARP_REPLY
};

int open_arp_socket()
{
    int sfd;

    if ((sfd = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ARP))) < 0) {
	perror("socket");
	exit(-2);
    }
    fcntl(sfd, F_SETFL, O_NDELAY);
    return sfd;
}
void bind_arp_socket(int s, char *device)
{
    struct sockaddr dst;

    dst.sa_family = AF_INET;
    strcpy(dst.sa_data, device);
    if (bind(s, (struct sockaddr *) &dst, sizeof dst)) {
	perror("bind");
    }
}
char *etheraddr_string(register const u_char * ep)
{
    static char hex[] = "0123456789abcdef";
    register u_int i, j;
    register char *cp;
    char buf[sizeof("00:00:00:00:00:00")];

    cp = buf;
    if ((j = *ep >> 4) != 0)
	*cp++ = hex[j];
    *cp++ = hex[*ep++ & 0xf];
    for (i = 5; (int) --i >= 0;) {
	*cp++ = ':';
	if ((j = *ep >> 4) != 0)
	    *cp++ = hex[j];
	*cp++ = hex[*ep++ & 0xf];
    }
    *cp = '\0';
    return (strdup(buf));
}

void send_arp_request(int s, char *device, u_int8_t eth_shost[ETH_ALEN], u_int8_t eth_dhost[ETH_ALEN], struct in_addr ip_shost, struct in_addr ip_dhost)
{
#define BUFLEN sizeof(struct ether_arp) + sizeof(struct ether_header)
    char buf[BUFLEN];
    struct ether_header *packethdr = (struct ether_header *) buf;
    struct ether_arp *packet = (struct ether_arp *) (packethdr + 1);
    struct sockaddr dst;

    bzero(buf, BUFLEN);
    memcpy(&(packethdr->ether_dhost), eth_dhost, ETH_ALEN);
    memcpy(&(packethdr->ether_shost), eth_shost, ETH_ALEN);
    packethdr->ether_type = htons(ETHERTYPE_ARP);
    packet->arp_hrd = htons(ARPHRD_ETHER);
    packet->arp_pro = htons(0x0800);
    packet->arp_hln = 6;
    packet->arp_pln = 4;
    packet->arp_op = htons(ARPOP_REQUEST);
    memcpy(&(packet->arp_sha), eth_shost, ETH_ALEN);
    memcpy(&(packet->arp_tha), eth_dhost, ETH_ALEN);
    *((struct in_addr *) (&(packet->arp_spa))) = ip_shost;
    *((struct in_addr *) (&(packet->arp_tpa))) = ip_dhost;
    dst.sa_family = AF_INET;
    strcpy(dst.sa_data, device);
    if (sendto(s, buf, sizeof(buf), 0, (struct sockaddr *) &dst, sizeof dst) < 0) {
	perror("write");
    }
}

enum arp_check_reply arp_check(register const u_char * bp, u_int length, u_int caplen, u_int8_t eth_shost[ETH_ALEN], struct in_addr ip_dhost)
{
    register const struct ether_arp *ap;
    register const struct ether_header *eh;
    register u_short pro, hrd, op;

    const u_char *snapend;
    snapend = bp + caplen + sizeof(struct ether_header);
    ap = (struct ether_arp *) (bp + sizeof(struct ether_header));
    if (((u_char *) (ap + 1) > snapend) || (length < sizeof(struct ether_arp))) {
	if (verbose)
	    fprintf(stderr, "Not enough received for this arp packet\n");
	return IGNORE_PACKET;
    }
    pro = EXTRACT_16BITS(&ap->arp_pro);
    hrd = EXTRACT_16BITS(&ap->arp_hrd);
    op = EXTRACT_16BITS(&ap->arp_op);

    if ((pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL)
	|| ap->arp_hln != sizeof((ap)->arp_sha)
	|| ap->arp_pln != sizeof((ap)->arp_spa)) {
	if (verbose)
	    fprintf(stderr, "Unknown arp protocol packet received\n");
	return IGNORE_PACKET;
    }
    if (pro == ETHERTYPE_TRAIL)
	if (verbose > 1)
	    (void) fprintf(stderr, "trailer-");
    eh = (struct ether_header *) bp;
    if (op != ARPOP_REPLY) {
	if (verbose)
	    fprintf(stderr, "Not an ARP REPLY\n");
	return IGNORE_PACKET;
    }
    if (EXTRACT_32BITS((ap)->arp_spa) != ntohl(ip_dhost.s_addr)) {
	if (verbose)
	    fprintf(stderr, "ARP reply for other ip adres\n");
	return IGNORE_PACKET;
    }
    if ((memcmp((char *) (eh)->ether_shost, eth_shost, 6)) == 0) {
	if (verbose)
	    (void) fprintf(stderr, "ieks, I have answerred myself");
	return ANSWERRED_MYSELF;
    }
    if ((memcmp((char *) (eh)->ether_dhost, eth_shost, 6)) != 0) {
	if (verbose)
	    (void) fprintf(stderr, "ieks, reply was not to me");
	return IGNORE_PACKET;
    }
    return ARP_REPLY;

}

void arp_print(register const u_char * bp, u_int length, u_int caplen)
{
    register const struct ether_arp *ap;
    register const struct ether_header *eh;
    register u_short pro, hrd, op;
    const u_char *snapend;
    static u_char ezero[6];

    snapend = bp + caplen + sizeof(struct ether_header);
    ap = (struct ether_arp *) (bp + sizeof(struct ether_header));

    if ((u_char *) (ap + 1) > snapend) {
	fprintf(stderr, "[|arp]");
	return;
    }
    if (length < sizeof(struct ether_arp)) {
	(void) fprintf(stderr, "truncated-arp");
	//default_print((u_char *)ap, length);
	return;
    }
    pro = EXTRACT_16BITS(&ap->arp_pro);
    hrd = EXTRACT_16BITS(&ap->arp_hrd);
    op = EXTRACT_16BITS(&ap->arp_op);

    if ((pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL)
	|| ap->arp_hln != sizeof((ap)->arp_sha)
	|| ap->arp_pln != sizeof((ap)->arp_spa)) {
	(void) fprintf(stderr, "arp-#%d for proto #%d (%d) hardware #%d (%d)",
		       op, pro, ap->arp_pln,
		       hrd, ap->arp_hln);
	return;
    }
    if (pro == ETHERTYPE_TRAIL)
	(void) fprintf(stderr, "trailer-");
    eh = (struct ether_header *) bp;
    switch (op) {

    case ARPOP_REQUEST:
	(void) fprintf(stderr, "arp who-has %s", inet_ntoa(*((struct in_addr *) (&((ap)->arp_tpa)))));
	if (memcmp((char *) ezero, (char *) (ap)->arp_tha, 6) != 0)
	    (void) fprintf(stderr, " (%s)", etheraddr_string((ap)->arp_tha));
	(void) fprintf(stderr, " tell %s", inet_ntoa(*((struct in_addr *) (&((ap)->arp_spa)))));
	if (memcmp((char *) (eh)->ether_shost, (char *) (ap)->arp_sha, 6) != 0)
	    (void) fprintf(stderr, " (%s)", etheraddr_string((ap)->arp_sha));
	break;

    case ARPOP_REPLY:
	(void) fprintf(stderr, "arp reply %s", inet_ntoa(*((struct in_addr *) (&((ap)->arp_spa)))));
	if (memcmp((char *) (eh)->ether_shost, (char *) (ap)->arp_sha, 6) != 0)
	    (void) fprintf(stderr, " (%s)", etheraddr_string((ap)->arp_sha));
	(void) fprintf(stderr, " is-at %s", etheraddr_string((ap)->arp_sha));
	if (memcmp((char *) (eh)->ether_dhost, (char *) (ap)->arp_tha, 6) != 0)
	    (void) fprintf(stderr, " (%s)", etheraddr_string((ap)->arp_tha));
	break;

    case ARPOP_RREQUEST:
	(void) fprintf(stderr, "rarp who-is %s tell %s",
		       etheraddr_string((ap)->arp_tha),
		       etheraddr_string((ap)->arp_sha));
	break;
    case ARPOP_RREPLY:
	(void) fprintf(stderr, "rarp reply %s at %s",
		       etheraddr_string((ap)->arp_tha),
		    inet_ntoa(*((struct in_addr *) (&((ap)->arp_tpa)))));
	break;

    default:
	(void) fprintf(stderr, "arp-#%d", op);
	//default_print((u_char *)ap, caplen);
	return;
    }
    fprintf(stderr, "\n");
    if (hrd != ARPHRD_ETHER)
	fprintf(stderr, " hardware #%d", hrd);
}
int get_arp_reply(int s, char *device, u_int8_t eth_shost[ETH_ALEN], struct in_addr ip_dhost, long timeout)
{
    struct timeval tv;
    fd_set rfds;
    int retval;
    struct sockaddr from;
    int fromlen;
    char *recver;
    enum arp_check_reply arp_check_return;
    struct ifreq ifr;
    int recverlen;

//      recver=malloc(1600);
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    if (ioctl(s, SIOCGIFMTU, &ifr) < 0) {
	perror("SIOCGIFMTU");
	exit(-2);
    }
    recverlen = ifr.ifr_mtu + 64;
    recver = malloc(recverlen);
    /* Watch socket (fd s) to see when it has input. */
    FD_ZERO(&rfds);
    FD_SET(s, &rfds);
    /* Wait up to five seconds. */
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = timeout % 1000;
    from.sa_family = AF_UNIX;
    strcpy(from.sa_data, device);
    while ((retval = select(s + 1, &rfds, NULL, NULL, &tv))) {
	fromlen = sizeof(from);
	retval = recvfrom(s, recver, 1550, 0, &from, &fromlen);
	if (retval < 0) {
	    perror("recvfrom");
	    exit(-2);
	}
	if (verbose)
	    arp_print(recver, retval, recverlen);
	arp_check_return = arp_check(recver, retval, recverlen, eth_shost, ip_dhost);
	if (arp_check_return == ARP_REPLY) {
	    free(recver);
	    return -1;
	}
    }
    if (verbose>1)
	fprintf(stderr, "Timeout ...\n");
    free(recver);
    return 0;
}
void print_version(void)
{

    fprintf(stderr, "Version "VERSION"\n");
}
void usage(void)
{
    print_version();
    fprintf(stderr, "Usage: %s [-Vhpqvv] [-c count] [-i interface] [-t timeout] address[/mask] ...\n",
	    program);
    exit(-3);
}

void lookup_hw_addr(int s, u_int8_t hwaddr[ETH_ALEN], char *device)
{
    struct ifreq ifr;
    struct sockaddr sa;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
	perror("SIOCGIFHWADDR");
	exit(-2);
    }
    sa = ifr.ifr_hwaddr;
    memcpy(hwaddr, sa.sa_data, ETH_ALEN);

}
int send_and_get_arp(int s, char *device, u_int8_t eth_shost[ETH_ALEN], u_int8_t eth_dhost[ETH_ALEN], struct in_addr ip_shost, struct in_addr ip_dhost, int timeout)
{
    send_arp_request(s, device, eth_shost, eth_dhost, ip_shost, ip_dhost);
    return (get_arp_reply(s, device, eth_shost, ip_dhost, timeout));
}
void set_ip_address(char *device, struct in_addr ip)
{
    int fd;
    struct ifreq ifr;
    struct sockaddr_in *sin;

    sin = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));

    memset(&ifr, 0, sizeof(ifr));
    memset(sin, 0, sizeof(struct sockaddr_in));

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	perror("socket");
	exit(-2);
    }
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    sin->sin_family = AF_INET;
    sin->sin_port = 0;
    sin->sin_addr = ip;
    memcpy((char *) &ifr.ifr_addr, (char *) sin, sizeof(struct sockaddr_in));

    if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
	perror("SIOCSIFADDR");
	exit(-2);
    }
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
	perror("SIOCGIFFLAGS");
	exit(-2);
    }
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
	perror("SIOCSIFFLAGS");
	exit(-2);
    }
    if (close(fd) < 0) {
	perror("close");
	exit(-2);
    }
    free(sin);
}
void unset_ip_address(char *device)
{
    int fd;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	perror("socket");
	exit(-2);
    }
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
	perror("SIOCGIFFLAGS");
	exit(-2);
    }
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
	perror("SIOCSIFFLAGS");
	exit(-2);
    }
    if (close(fd) < 0) {
	perror("close");
	exit(-2);
    }
}
void enable_network(char *device)
{
    int fd;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	perror("socket");
	exit(-2);
    }
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
	perror("SIOCGIFFLAGS");
	exit(-2);
    }
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
	perror("SIOCSIFFLAGS");
	exit(-2);
    }
    if (close(fd) < 0) {
	perror("close");
	exit(-2);
    }
}
void init_random()
{
    struct timeval tv;

    gettimeofday(&tv, 0);
    srandom(tv.tv_sec);
}
void grab_next_ip(struct in_addr *ip_dhost, struct add_mask_t *add_mask, unsigned int add_mask_count)
{
    unsigned int hit, hit2, count;
    struct add_mask_t *p = add_mask;

    hit = (unsigned int) ((float) add_mask_count * random() / (RAND_MAX + 1.0));
    p+=hit;
    if (hit >= add_mask_count) {
	fprintf(stderr, "Oops, internal random function error\n");
	exit(-4);
    }
    count = 1 << (32 - (add_mask + hit)->prefix);
    switch ((add_mask + hit)->prefix) {
    case 32:
	ip_dhost->s_addr = htonl(ntohl(p->address.s_addr));
	break;
    case 31:
	hit2 = (unsigned int) ((float) count * random() / (RAND_MAX + 1.0));
	ip_dhost->s_addr = htonl(ntohl(p->address.s_addr) + hit2);
	break;
    default:
	count--;
	count--;
	hit2 = 1 + (unsigned int) ((float) count * random() / (RAND_MAX + 1.0));
	ip_dhost->s_addr = htonl(ntohl(p->address.s_addr) + hit2);
	break;
    }

    if (verbose > 1)
	fprintf(stderr, "OK, we found argument:%d(of %d) address:%s", hit, add_mask_count, inet_ntoa(*ip_dhost));
    if (verbose > 1)
	fprintf(stderr, "(%s/%d)\n", inet_ntoa(p->address), p->prefix);
}

int main(int argc, char **argv)
{
    int c, s, i;
    char *device = "eth0";
    u_int8_t eth_shost[ETH_ALEN];
    u_int8_t eth_dhost[ETH_ALEN] =
    {255, 255, 255, 255, 255, 255};
    struct in_addr ip_shost, ip_dhost;
    long timeout = 300;
    int probeonly = 0;
    long int count = 0;
    int option_index = 0;
    unsigned int add_mask_count = 0;

    static struct option long_options[] =
    {
	{"version", 0, 0, 'V'},
	{"help", 0, 0, 'h'},
	{"probeonly", 0, 0, 'p'},
	{"quiet", 0, 0, 'q'},
	{"verbose", 0, 0, 'v'},
	{"moreverbose", 0, 0, 2},
	{"timeout", 1, 0, 't'},
	{"interface", 1, 0, 'i'},
	{"count", 1, 0, 'c'},
	{0, 0, 0, 0}
    };
    struct add_mask_t *add_mask;

    program = argv[0];

    if (inet_aton("0.0.0.0", &ip_shost) < 0) {
	perror("inet_aton");
	exit(-3);
    }
    init_random();
    while ((c = getopt_long(argc, argv, "c:hi:pqt:vV", long_options, &option_index)) != EOF) {

	switch (c) {
	case 2:
	    verbose += 2;
	    break;
	case 'V':
	    print_version();
	    break;
	case 'p':
	    probeonly = 1;
	    break;
	case 'q':
	    quiet = 1;
	    verbose = 0;
	    break;
	case 'v':
	    verbose++;
	    quiet = 0;
	    break;
	case 't':
	    timeout = atol(optarg);
	    if (verbose > 1)
		fprintf(stderr, "Timeout set to %ld\n", timeout);
	    break;
	case 'i':
	    device = optarg;
	    break;
	case 'c':
	    count = atol(optarg);
	case 0:
	    break;
	default:
	    usage();
	    break;
	}
    }
    if (optind < argc) {
	int i;
	register unsigned int prefix;
	struct add_mask_t *p;
	add_mask = malloc(sizeof(struct add_mask_t) * (argc - optind));

	p = add_mask;
	for (i = optind; i < argc; i++, p++, add_mask_count++) {
	    char *slash, *end;

	    if ((slash = strchr(argv[i], '/')) == NULL) {
		p->netmask.s_addr = INADDR_NONE;
		p->prefix = 32;
	    } else {
		*slash++ = '\0';
		if (strchr(slash, '.') != NULL)
		    inet_aton(slash, &(p->netmask));
		else {
		    prefix = strtoul(slash, &end, 0);
		    if (*end != '\0') {
			*(slash - 1) = '/';
			fprintf(stderr, "argument is not address[/mask] : %s\n", argv[i]);
			exit(-3);
		    }
		    if (prefix != 32)
			p->netmask.s_addr = htonl(~(0xffffffffU >> prefix));
		    else
			p->netmask.s_addr = INADDR_NONE;
		}

	    }
	    if (!inet_aton(argv[i], &(p->address))) {
		if (slash != NULL)
		    *(slash - 1) = '/';
		fprintf(stderr, "argument is not address[/mask] : %s\n", argv[i]);
		exit(-3);
	    }
	    p->address.s_addr = (p->address.s_addr) & (p->netmask.s_addr);
	    if (verbose > 2)
		fprintf(stderr, "Processing argument %d: %s .. resulting in %s/", i, argv[i], inet_ntoa(p->address));
	    if (verbose > 2)
		fprintf(stderr, " %s(%d) - ", inet_ntoa(p->netmask), p->prefix);
	    for (prefix = 0; prefix < 32; prefix++) {
		if ((ntohl(p->netmask.s_addr) & (1 << (31 - prefix))) == 0)
		    break;
	    }
	    if (verbose > 2)
		fprintf(stderr, "%d\n", prefix);
	    p->prefix = prefix;
	}
    } else {
	fprintf(stderr, "No address/mask\n");
	exit(-3);
    }
    if(!probeonly)enable_network(device);

    s = open_arp_socket();

    bind_arp_socket(s, device);

    lookup_hw_addr(s, eth_shost, device);

    if (verbose > 1)
	fprintf(stderr, "HW addr is:%s\n", etheraddr_string(eth_shost));

    for (i = 0; (i<count||count==0); i++) {
	grab_next_ip(&ip_dhost, add_mask, add_mask_count);
	if (send_and_get_arp(s, device, eth_shost, eth_dhost, ip_shost, ip_dhost, timeout) < 0) {
	    if (verbose)
		fprintf(stderr, "IP taken !\n");
	    if (probeonly)
		return 1;
	} else {
	    if (!probeonly)
		{
	    	set_ip_address(device, ip_dhost);
	    	if (send_and_get_arp(s, device, eth_shost, eth_dhost, ip_shost, ip_dhost, timeout) < 0) {
			if (verbose)
			    fprintf(stderr, "IP taken !!\n");
			unset_ip_address(device);
		    } else {
			if (quiet == 0)
			    printf("IP adress: %s\n", inet_ntoa(ip_dhost));
			if (close(s) < 0) {
			    perror("close");
			    exit(-2);
			}
			return 0;
		    }
		}
	}
    }
    if (quiet == 0)
	printf("NO ip found\n");
    if (close(s) < 0) {
	perror("close");
	exit(-2);
    }
    if (probeonly) return 0;
    return 1;
}
