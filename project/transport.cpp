#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <list>

#include "consts.h"
#include "packet.h"

#define BUFFER_SIZE 1012

// Main function of transport layer; never quits
void listen_loop(int sockfd, struct sockaddr_in* addr, int type,
                 ssize_t (*input_p)(uint8_t*, size_t),
                 void (*output_p)(uint8_t*, size_t)) {
    
    socklen_t addr_len = sizeof(struct sockaddr_in);
    
    /* Perform 3-Way Handshake */
    if(type == SERVER) {
        
        uint8_t server_recv_handshake_buffer[sizeof(packet) + MSS] = {0};
        uint8_t server_send_handshake_buffer[sizeof(packet) + MSS] = {0};

        // 1. Receive client SYN
        int bytes_recvd = recvfrom(sockfd, server_recv_handshake_buffer, MSS,
            0, (struct sockaddr*)addr, &addr_len);
        if(bytes_recvd < 0 ) {
           perror("Error receiving client SYN");
        }
        packet* server_recv_pkt = (packet*) server_recv_handshake_buffer;
        fprintf(stderr, "Client seq: %d received, flags=%d\n", htons(server_recv_pkt->seq), server_recv_pkt->flags);


        // 2. Send back SYN ACK

        // Equivalent: char ack[] = "ACK 457, SEQ 789, SYN, ACK";
        uint16_t ack = htons(server_recv_pkt->seq) + 1, seq_num = rand() % 1000, flags = 0x3; // 0x3 = 011 - PARITY=0, SYN=1, ACK=1

        make_handshake_packet(server_send_handshake_buffer, nullptr, 0, seq_num, ack, flags);

        if(bytes_recvd > 0){ // TODO: This should check for SYN ACK details
            int did_send = sendto(sockfd, server_send_handshake_buffer, sizeof(server_send_handshake_buffer), 0, (struct sockaddr*)addr, addr_len);
            if(did_send) {
                fprintf(stderr, "sent server SYN ACK\n");
            }
        }

        // 3. Receive last ACK
        bytes_recvd = recvfrom(sockfd, server_recv_handshake_buffer, MSS,
            0, (struct sockaddr*)addr, &addr_len);
        if(bytes_recvd > 0){
            fprintf(stderr, "Client seq: %d received, flags=%d\n", htons(server_recv_pkt->seq), server_recv_pkt->flags);
        }
    }

    if(type == CLIENT){
        // 1. Send first SYN
        
        uint8_t client_send_handshake_buffer[sizeof(packet) + MSS] = {0};
        uint8_t client_recv_handshake_buffer[sizeof(packet) + MSS] = {0};
        
        // char syn_buff[] = "SYN SEQ= random: 1-1000";
        uint16_t ack = 0, seq_num = rand() % 1000, flags = 0x1; // 0x1 = 001 - PARITY=0, SYN=0, ACK=1
        make_handshake_packet(client_send_handshake_buffer, nullptr, 0, seq_num, ack, flags);

        int did_send = sendto(sockfd, client_send_handshake_buffer, sizeof(client_send_handshake_buffer),
            0, (struct sockaddr*)addr, addr_len);

        if(did_send){
            fprintf(stderr, "sent first client SYN\n");
        }

        // 2. Receive SYN from Server
        int bytes_recvd = recvfrom(sockfd, client_recv_handshake_buffer, MSS, 0, (struct sockaddr*)addr, &addr_len);
        
        if (bytes_recvd > 0){
            
            packet* client_recv_pkt = (packet*) client_recv_handshake_buffer;

            fprintf(stderr, "Server seq: %d received, flags=%d\n", htons(client_recv_pkt->seq), client_recv_pkt->flags);
            
            // char syn_ack_buff[] = "ACK 790, SEQ 457, ACK";
            ack = htons(client_recv_pkt->seq) + 1, seq_num = htons(client_recv_pkt->ack), flags = 0x1; // 0x1 = 001 - PARITY=0, SYN=0, ACK=1

            make_handshake_packet(client_send_handshake_buffer, nullptr, 0, seq_num, ack, flags);

            // 3. Send final ACK back to server
            sendto(sockfd, client_send_handshake_buffer, sizeof(client_send_handshake_buffer),
            0, (struct sockaddr*)addr, addr_len);
            
            if(did_send) {
                fprintf(stderr, "sent last client SYN\n");
            }
        }
    }    


    // TODO: Enforce Size as Flow Window ; Default size is MSS
    std::list<packet *> send_buffer;
    std::list<packet *> recv_buffer;

    fprintf(stderr, "Beginning listening loop..\n");
    int seq_num = 0;

    /* Normal State */
    while (true) {
        uint8_t data_buff[MSS]; uint16_t nread;

        // Sending Data
        if(type == CLIENT) {
            
            char buf[sizeof(packet) + MSS] = {0};

            // Send until window is full
            while(send_buffer.size() < 15){
                nread = input_p(data_buff, MSS);
                if(nread){
                    //Encode packet to send
                    packet* pkt = (packet*) buf;
                    pkt->seq = htons(seq_num);
                    pkt->ack = htons(0);
                    memcpy(pkt->payload, data_buff, nread);
                    pkt->length = nread;


                    int did_send = sendto(sockfd, pkt, sizeof(packet) + MSS,
                    0, (struct sockaddr*)addr, addr_len);

                    if(did_send){
                        // Add packet to sending buffer
                        fprintf(stderr, "sent packet %d to server\n", seq_num);
                        send_buffer.push_back(pkt);
                        seq_num++;
                    }
                }
            }
        }

        // Receiving data
        if(type == SERVER){
            //Decocde packet
            char buf[sizeof(packet) + MSS] = {0};
            packet* pkt = (packet*) buf;
            
            int bytes_recvd = recvfrom(sockfd, pkt, sizeof(packet) + MSS,
                0, (struct sockaddr*)addr, &addr_len);
            if(bytes_recvd <= 0) continue;

            uint16_t ack = ntohs(pkt->ack);
            uint16_t seq = ntohs(pkt->seq);
            bool ack_flag = (pkt->flags >> 1) & 1;

            //If ACK is set, remove previously ACKed packets from sending buffer
            if(ack_flag){
                std::list<packet*>::iterator i = send_buffer.begin();
                while(i != send_buffer.end())
                {
                    if(ntohs((*i)->seq) < ack)
                        i = send_buffer.erase(i);
                    else
                        i++;
                }
            }

            // Place the packet in a receiving buffer
            recv_buffer.push_back(pkt);

            // TODO: Do a linear scan of all the packets in the receiving buffer starting with the next SEQ you expect and write their contents to standard output
            packet* output_pkt = recv_buffer.front();
            fprintf(stderr, "Reading packet %d: %s", ntohs(output_pkt->seq), output_pkt->payload);
            recv_buffer.pop_front();

            // TODO: Send back ACK
            packet* ack_pkt = (packet*) buf;
            pkt->seq = htons(seq++);
            pkt->ack = htons(seq++);

            sendto(sockfd, ack_pkt, sizeof(packet) + MSS,
                    0, (struct sockaddr*)addr, addr_len);
        }
    }
}
