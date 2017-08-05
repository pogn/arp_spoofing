#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

#define ETHERNET_ADDR_LEN 6
struct ethernet_header {
    u_int8_t ethernet_dhost[ETHERNET_ADDR_LEN];
    u_int8_t ethernet_shost[ETHERNET_ADDR_LEN];
    uint16_t ether_type;            /* IP? ARP? etc */
};

#define ARP_REQUEST 1   /* ARP Request             */
#define ARP_REPLY 2     /* ARP Reply               */
#pragma push(1)
struct arp_header
{
    u_int16_t htype;    /* Hardware Type           */
    u_int16_t ptype;    /* Protocol Type           */
    u_int8_t hlen;      /* Hardware Address Length */
    u_int8_t plen;      /* Protocol Address Length */
    u_int16_t oper;     /* Operation Cdode          */
    u_int8_t sha[6];      /* Sender hardware address */
    struct in_addr spa_inaddr; /* Sender IP address       */
    u_int8_t tha[6];      /* Target hardware address */
    struct in_addr tpa_inaddr; /* Target IP address       */
};
#pragma pack(pop)
void GrapMyMacIP(char* myMac);

int main(int argc, char *argv[])
{
    setbuf(stdout, NULL);
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    //char filter_exp[] = "port 80";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_int8_t *packet;	/* The actual packet */
    int res,i,k,num;
    struct ethernet_header *pEth, *Eth_req;
    struct arp_header *pArp, *Arp_req;
    //struct sndRQ;
    char *myMac,*myIP,*targetIP, *tmp;
    int len;
    struct ifreq s;
    struct in_addr ipAddr; // to save binary IP address

    printf("%d \n", sizeof(*pArp));
/* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

    if (argc != 4){
       fprintf(stderr,"Usage: [device_name] [Sender IP] [Target IP]");
    }

    dev=argv[1];
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

/* make REQUEST */
    Eth_req = (struct ethernet_header*)malloc(sizeof(struct ethernet_header));
    Arp_req = (struct arp_header*)malloc(sizeof(struct arp_header));

//Ethnet header
    for (i = 0; i<6 ; i++){
        Eth_req->ethernet_dhost[i] = 0xff;
    }
    Eth_req->ether_type = 0x608;

    Arp_req -> htype = htons('\x00\x01');
    Arp_req -> ptype = htons('\x08\x00');
    Arp_req -> hlen = '\x06';
    Arp_req -> plen = '\x04';
    Arp_req -> oper = htons('\x00\x01');


    //my Mac address and IP addr
    myMac= (char *)malloc(10); // you need to allocate

//MAC
    //attacker mac
    int soc = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(myMac, argv[1], sizeof(argv[1]));
    strncpy(s.ifr_name, dev, IFNAMSIZ);
    if(ioctl(soc, SIOCGIFHWADDR, &s)==0){
        int i;
        for( i = 0 ; i < 6 ; ++i)
        {
            Arp_req -> sha[i] = s.ifr_addr.sa_data[i] ;
            Eth_req -> ethernet_shost[i] = s.ifr_addr.sa_data[i] ;
            printf("%02x:", s.ifr_addr.sa_data[i]);
        }
    }
    //targ

    printf("\n");

//IP
    targetIP = (char *)malloc(20);
    myIP = (char *)malloc(20);
    tmp = (char *)malloc(20);

    //attacker ip
   inet_pton(AF_INET, argv[2], &(Arp_req->spa_inaddr));
   inet_pton(AF_INET, argv[3], &(Arp_req->tpa_inaddr));//Arp_req -> tpa_inaddr.s_addr);
   printf("IP : %X\n", Arp_req -> tpa_inaddr.s_addr);
    //Arp_req -> tpa_inaddr.s_addr = argv[3];
/*

            strcpy(myIP, argv[2]);
    inet_pton(AF_INET, argv[2], &ipAddr.s_addr);//, sizeof(tmp));//&ipAddr.s_addr);

    printf("IP : %s\n", ipAddr.s_addr);
    printf("dd");
    for( i = 0 ; i < 4 ; ++i){
       // Arp_req -> spa[i] = ipAddr.s_addr[i] ;
    }
    //target ip
    strcpy(targetIP, argv[3]);
    inet_pton(AF_INET, argv[3], &ipAddr.s_addr);
    for( i = 0 ; i < 4 ; ++i){
        //Arp_req -> tpa[i] = ipAddr.s_addr[i];
    }
*/
    // connect two structure
    packet = (char*)malloc(sizeof(Arp_req) + sizeof(Eth_req));
    memcpy(packet,Eth_req,sizeof(Eth_req));
    memcpy(packet+sizeof(Eth_req),Arp_req,sizeof(Arp_req));

    printf("packet:%d",sizeof(packet));

    //send packet
    if (pcap_sendpacket(handle, packet, 100 /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(soc));
        return;
    }

    /* grap REPLY packet */
    num=0;
    while((res = pcap_next_ex(handle, &header, &packet))>=0){ //double pointer
        if(res==0) {continue;}
        num++;
        if(num ==1)
            break;
        //}

        /* Print its length */
        printf("Length [%d]\n", header->len);

        /* calc size of ARP heaer */
        pEth = (struct ethernet_header *)packet;
        pArp = (struct arp_header *)(packet + sizeof(*pEth));

        /* check ARP? */
        if(pEth->ether_type!=0x0806)
        {
            num--; printf("hey");
            continue;
            fprintf(stderr, "-----------------------This is not ARP packet----------------------");
        }

/*
        // print ehternet
        fprintf(stdout, "DESTINATION MAC Address - [");
        for( i = 0 ; i < 6 ; ++i)
        {
            fprintf(stdout, "%02X:", pEth->ether_dhost[i]);
        }
        fprintf(stdout, "\b]\t\t\n");

        fprintf(stdout, "SOURCE      MAC Address - [");
        for( i= 0 ; i < 6 ; ++i)
        {
            fprintf(stdout, "%02X:", pEth->ether_shost[i]);
        }
        fprintf(stdout, "\b]\n");

        // print IP
        char tmp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(pIph->ip_src), tmp, INET_ADDRSTRLEN);
        fprintf(stdout, "SOURCE IP address       - [%s]\n", tmp); //inet_ntoa(pIph->ip_src));
        inet_ntop(AF_INET, &(pIph->ip_dst), tmp, INET_ADDRSTRLEN);
        fprintf(stdout, "DESTINATION IP address  - [%s]\n", tmp);//inet_ntoa(pIph->ip_dst));

        // print TCP
        fprintf(stdout, "SOURCE port             - [%hu]\n", ntohs(pTcp->th_sport)); //recommandation - befor using %hu, print "%02x" to see real hex value
        fprintf(stdout, "DESTINATION port        - [%hu]\n", ntohs(pTcp->th_dport)); //without ntohs, it will read memory "little endian"


        printf("-------------------------------------------------\n");
    }
*/
    /* And close the session */
    pcap_close(handle);
    return(0);

    }
}

void GrapMyMacIP(char* myMac)//, char* myIP)
{
    //int retval;
    //retval = system('ifconfig');
    //printf("Exit Status %d\n",retval);
    char returnData[64];
    FILE *fp;
    fp = popen("/sbin/ifconfig eth0", "r");

    fgets(returnData, 64, fp); //read file stream in this
    fgets(returnData, 64, fp);
    //printf("%d", sizeof(returnData));
    char *ptr = strtok(returnData, " ");
    ptr = strtok(NULL, " ");
    printf("%s", ptr);

    fgets(returnData, 64, fp);
    fgets(returnData, 64, fp);
    ptr = strtok(returnData, " ");
    ptr = strtok(NULL, " ");
    printf("%s", ptr);
    /*
    strcpy(s.ifr_name, argv[1]);
    if( ioctl(fd, SIOCGIFHWADDR, &s) == 0){
        int i;
        for(i=0; i<6; i++){
            packet[6+i] = s.ifr_addr.sa_data[i];
            packet[22+i] = s.ifr_addr.sa_data[i];
        }
    }
    */
    printf("%s", ptr);
    //printf("%c %c %c %c",returnData[12],returnData[14], returnData[16],returnData[7]);
    int i=0;
    /*
    while(1){
        if (returnData[i])
        i++;
    }*/

    pclose(fp);
}

