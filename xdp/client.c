#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

#define BUFSIZE 1024
// void error_handling(char * message);

typedef struct test_network_packet{
    unsigned long id;
    // struct timeval send_time;
} pkt;

int main(int argc, char * argv[]){
    // char message[BUFSIZE];
    int sock;
    // socklen_t adr_sz;
    unsigned long i;
    i = -1;
    pkt * test = (pkt*)malloc(sizeof(pkt));

    char * server_ip = "43.153.192.5";

    // struct sockaddr_in serv_adr, from_adr;
    struct sockaddr_in serv_adr;
    if (argc!=2){
        printf("usage: %s <port_number>\n", argv[0]);
        exit(1);
    }

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    
    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = inet_addr(server_ip);
    serv_adr.sin_port = htons(atoi(argv[1]));

    while (1){
        i ++;
        test->id = htonl(i);
        sendto(sock, (char*)test, sizeof(pkt), 0, (struct sockaddr*)&serv_adr, sizeof(serv_adr));
        printf("the msg sent: %d\n", ntohl(test->id));
        usleep(100);
        // sleep(1);
        // if (i%30 == 0 && i!=0) {
        //     sleep(10);
        // }
    }
    printf("sock closing\n");
    close(sock);
    return 0;
}

