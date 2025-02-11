#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "consts.h"

ssize_t PAYLOAD_SIZE = 10;
ssize_t BUFFER_SIZE = 1024;

ssize_t send_packets(uint8_t* buffer, ssize_t bytes_read, uint16_t* seq_num);


// Main function of transport layer; never quits
void listen_loop(int sockfd, struct sockaddr_in* addr, int type,
                 ssize_t (*input_p)(uint8_t*, size_t),
                 void (*output_p)(uint8_t*, size_t)) {

    uint8_t buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    uint16_t seq_num = 0; 

    // chop into packets
    while (true) {
        
        // function to read 
        bytes_read = input_p(buffer, sizeof(buffer));
        send_packets(buffer, bytes_read, &seq_num);

    }
}

ssize_t send_packets(uint8_t* buffer, ssize_t bytes_read, uint16_t* seq_num) {
    if (bytes_read <= 0) {
        return 0; // No data to process
    }

    printf("Bytes read: %zd\n", bytes_read);

    ssize_t num_packets = (bytes_read + (PAYLOAD_SIZE - 1)) / PAYLOAD_SIZE;

    for (int i = 0; i < num_packets; i++) {
        printf("Packet created!\n");

        uint8_t buf[sizeof(packet) + MSS] = {0}; // Allocate memory for packet
        packet* pkt = (packet*) buf;            // Cast to packet structure

        pkt->seq = ntohs(*seq_num);

        // Determine payload boundaries
        size_t payload_start = i * PAYLOAD_SIZE;
        size_t payload_end = (i + 1) * PAYLOAD_SIZE;
        if (payload_end > bytes_read) {
            payload_end = bytes_read;
        }
        size_t payload_len = payload_end - payload_start;

        memcpy(pkt->payload, buffer + payload_start, payload_len); // Copy payload

        (*seq_num)++; // Increment sequence number

        printf("Sequence number: %hu\n", ntohs(pkt->seq));
        printf("Payload: %.*s\n", (int)payload_len, pkt->payload);
    }

    return num_packets; // Return the number of packets processed
}


