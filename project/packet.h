#include <stdint.h>
#include <stdio.h>
#include "consts.h"

void make_handshake_packet(uint8_t* buf, uint8_t* data_buffer, ssize_t data_len, uint16_t seq_num, uint16_t ack, uint16_t flags);

void make_packet(uint8_t* buf, uint16_t seq_num);

ssize_t recv_packet(uint8_t* recv_buffer, ssize_t bytes_recv);

void set_parity_bit(packet* pkt);

bool verify_parity(packet* pkt);

ssize_t send_packets(uint8_t* write_buffer, ssize_t bytes_read, uint16_t* seq_num);
