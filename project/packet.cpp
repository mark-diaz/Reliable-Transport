#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "consts.h"
#include <list>


void make_handshake_packet(uint8_t* buf, uint8_t* data_buffer, ssize_t data_len, uint16_t seq_num, uint16_t ack, uint16_t flags) {

    printf("Creating Ack Packet!\n");
    packet* pkt = (packet*) buf;

    // Set header fields:
    pkt->seq = htons(seq_num);       // Seq number
    pkt->ack = htons(ack);       // Ack number
    pkt->length = htons(data_len);  // Size of Payload
    pkt->win = htons(512);     // Window size
    pkt->flags = flags;   // Flags: (hex: 0x3 = 110 - SYN=1, ACK=1, Parity=0 )
    pkt->unused = htons(0);    // Unused field

    // Copy the data buffer into the payload (if data_len > 0)
    if (data_len > 0 && data_buffer != nullptr) {
        memcpy(pkt->payload, data_buffer, data_len);
    }
    // send packet

}

// Helper function for debugging:
void make_packet(uint8_t* buf, uint16_t seq_num) {

    printf("Making Packet!\n");
    packet* pkt = (packet*) buf;

    // Set header fields:
    pkt->seq = htons(seq_num);       // Seq number
    pkt->ack = htons(2);       // Ack number
    pkt->length = htons(PAYLOAD_SIZE);  // Length of payload
    pkt->win = htons(512);     // Window size
    pkt->flags = 0x1;   // Flags: Parity=0, ACK=0, SYN=1 (hex: 0x3 = 110)
    pkt->unused = htons(0);    // Unused field

    uint8_t packet_data[PAYLOAD_SIZE];

    for (int i = 0; i < 26; i++) {
        packet_data[i] = 'A' + (i % 26);  // Fill with 'A', 'B', 'C', etc.
    }

    memcpy(pkt->payload, packet_data, PAYLOAD_SIZE);

}


ssize_t send_packets(uint8_t* write_buffer, ssize_t bytes_read, uint16_t* seq_num) {

    if (bytes_read <= 0) {
        return 0;
    }

    printf("Bytes read: %zd\n", bytes_read);

    // Round up to calculate packets to send
    ssize_t num_packets = (bytes_read + (PAYLOAD_SIZE - 1)) / PAYLOAD_SIZE;

    // For each packet
    for (int i = 0; i < num_packets; i++) {

        printf("Packet created!\n");

         // Allocate memory for packet
        uint8_t buf[sizeof(packet) + MSS] = {0};
        // Cast to packet structure
        packet* pkt = (packet*) buf;
        pkt->seq = ntohs(*seq_num);

        // Determine payload boundaries
        size_t payload_start = i * PAYLOAD_SIZE;
        size_t payload_end = (i + 1) * PAYLOAD_SIZE;
        if (payload_end > bytes_read) {
            payload_end = bytes_read;
        }
        size_t payload_len = payload_end - payload_start;

        // Write to packet
        memcpy(pkt->payload, write_buffer + payload_start, payload_len); // Copy payload

        // Increment sequence number
        (*seq_num)++;

        printf("Sequence number: %hu\n", ntohs(pkt->seq));
        printf("Payload: %d %s\n", (int)payload_len, pkt->payload);

        // send the packets

    }

    return num_packets;
}

ssize_t recv_packet(uint8_t* recv_buffer, ssize_t bytes_recv) {
    if (bytes_recv <= 0) {
        return 0;
    }

    // Process each packet
    printf("Receiving packet!\n");
    packet* pkt = (packet*) recv_buffer;

    printf("Payload received: %d %s Seq: #%d\n", (int)bytes_recv, pkt->payload, htons(pkt->seq));

    // handle integrity

    return 0;
}

void set_parity_bit(packet* pkt) {
    // Calculate the number of 1s in the packet
    int count = bit_count(pkt);

    // Determine the parity bit (even parity)
    uint8_t parity_bit = (count % 2 == 0) ? 0 : 1;

    // Set the parity bit in the packet
    pkt->flags &= ~0x4;  // Clear the parity bit (assuming it's the 3rd bit in flags)
    pkt->flags |= (parity_bit << 2);  // Set the parity bit (shift to the 3rd bit position)
}

bool verify_parity(packet* pkt) {
    int count = bit_count(pkt);
    return (count % 2 == 0);  // Should return true if parity is correct
}

/*
Example uses of functions:

    uint8_t write_buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    uint16_t seq_num = 0;

    // Create fake packet:
    uint8_t buf[sizeof(packet) + PAYLOAD_SIZE];
    make_packet(buf, 10);


    recv_packet(buf, sizeof(packet) + PAYLOAD_SIZE);


    // chop into packets
    while (true) {

    //  function to read
        bytes_read = input_p(write_buffer, sizeof(write_buffer));
        send_packets(write_buffer, bytes_read, &seq_num);

    }

*/