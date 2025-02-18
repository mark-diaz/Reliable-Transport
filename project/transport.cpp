#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <list>
#include <sys/socket.h>
#include <bitset>
#include <fcntl.h>

#include "consts.h"
#include "packet.h"

uint16_t get_buffer_size(std::list<packet> buff);

uint16_t recv_win = MAX_WINDOW;

// Updates when receiving new packets
uint16_t their_recv_win =  MAX_WINDOW;

uint16_t seq_num = 0;
uint16_t expecting_seq = 0;

std::list<packet> send_buffer;
std::list<packet> recv_buffer;


// Remove acknowledged packets from buffer
void ack_buffer(std::list<packet>& buff, uint16_t ack){
    std::list<packet>::iterator i = buff.begin();
    while(i != buff.end())
    {
        if(ntohs((*i).seq) <= ack)
            i = buff.erase(i);
        else
            i++;
    }
}

// Insert packet into buffer based on sequence number
void insert_packet(std::list<packet>& buff, const packet& new_packet) {
    auto it = buff.begin();
    while (it != buff.end() && ntohs(it->seq) < ntohs(new_packet.seq)) {
        ++it;
    }
    buff.insert(it, new_packet);
}

// Output data from buffer and return next expected sequence number
uint16_t read_buffer(std::list<packet>& buff,
                    void (*output_p)(uint8_t*, size_t)){
    std::list<packet>::iterator i = buff.begin();
    while(i != buff.end() )
    {
        // fprintf(stderr, "Expecting packet %d , seeing %d\n", expecting_seq, ntohs((*i).seq));

        if(ntohs((*i).seq) == expecting_seq){
            output_p((*i).payload, ntohs((*i).length));
            i = buff.erase(i);
            expecting_seq++;
        }
        // Packet did not match expected sequence
        else break;
    }
    return expecting_seq;
}

// Main function of transport layer; never quits
void listen_loop(int sockfd, struct sockaddr_in* addr, int type,
                 ssize_t (*input_p)(uint8_t*, size_t),
                 void (*output_p)(uint8_t*, size_t)) {

    socklen_t addr_len = sizeof(struct sockaddr_in);

    /* Perform 3-Way Handshake */
    if(type == SERVER) {
        srand(time(0));
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
        uint16_t ack = htons(server_recv_pkt->seq) + 1, flags = 0x3;
        // 0x3 = 011 - PARITY=0, SYN=1, ACK=1
        seq_num = rand() % 1000;

        make_handshake_packet(server_send_handshake_buffer, nullptr, 0, seq_num, ack, flags);

        // set parity
        packet* server_send_pkt = (packet*) server_send_handshake_buffer;
        set_parity_bit(server_send_pkt);

        if(bytes_recvd > 0){ // TODO: This should check for SYN ACK details
            int did_send = sendto(sockfd, server_send_handshake_buffer, sizeof(server_send_handshake_buffer), 0, (struct sockaddr*)addr, addr_len);
            if(did_send) {
                fprintf(stderr, "sent server SYN ACK Seq:%d, ACK: %d, Flags: %d \n", seq_num, ack, flags);
                expecting_seq = ack;
                seq_num ++;
            }
        }

        // 3. Receive last ACK
        bytes_recvd = recvfrom(sockfd, server_recv_handshake_buffer, MSS,
            0, (struct sockaddr*)addr, &addr_len);

        if(bytes_recvd > 0){
            if(htons(server_recv_pkt->seq) != 0){
                expecting_seq = htons(server_recv_pkt->seq) + 1;
            }

            fprintf(stderr, "Client seq: %d received, flags=%d\n", htons(server_recv_pkt->seq), server_recv_pkt->flags);
        }
    }


    if(type == CLIENT){
        srand(time(0)+1);

        // 1. Send first SYN

        uint8_t client_send_handshake_buffer[sizeof(packet) + MSS] = {0};
        uint8_t client_recv_handshake_buffer[sizeof(packet) + MSS] = {0};

        // char syn_buff[] = "SYN SEQ= random: 1-1000";
        uint16_t ack = 0, flags = 0x1;
        seq_num = rand() % 1000 ; // 0x1 = 001 - PARITY=0, SYN=0, ACK=1
        make_handshake_packet(client_send_handshake_buffer, nullptr, 0, seq_num, ack, flags);

        int did_send = sendto(sockfd, client_send_handshake_buffer, sizeof(client_send_handshake_buffer),
            0, (struct sockaddr*)addr, addr_len);

        if(did_send){
            fprintf(stderr, "sent first client SYN\n");
        }

        // 2. Receive SYN ACK from Server
        int bytes_recvd = recvfrom(sockfd, client_recv_handshake_buffer, MSS, 0, (struct sockaddr*)addr, &addr_len);

        if (bytes_recvd > 0){

            packet* client_recv_pkt = (packet*) client_recv_handshake_buffer;

            fprintf(stderr, "Server seq: %d received, flags=%d\n", htons(client_recv_pkt->seq), client_recv_pkt->flags);

            // char syn_ack_buff[] = "ACK 790, SEQ 457, ACK";
            ack = htons(client_recv_pkt->seq) + 1, seq_num = htons(client_recv_pkt->ack), flags = 0x1; // 0x1 = 001 - PARITY=0, SYN=0, ACK=1
            expecting_seq = ack;


            // 3. Send final ACK back to server
            // Check if need to send with data
            uint8_t data_buff[MSS]; uint16_t input_read;
            uint16_t next_seq_num = (input_read) ? seq_num : 0;

            make_handshake_packet(client_send_handshake_buffer, data_buff, input_read, next_seq_num, ack, flags);

            // Data was sent, update sequence number and add to sending buffer
            if(next_seq_num){
                fprintf(stderr, "I piggyback data!");
                seq_num++;
            }

            // set parity
            packet* client_send_pkt = (packet*) client_send_handshake_buffer;
            set_parity_bit(client_send_pkt);

            sendto(sockfd, client_send_handshake_buffer, sizeof(client_send_handshake_buffer),
            0, (struct sockaddr*)addr, addr_len);

            if(did_send) {
                fprintf(stderr, "sent last client SYN\n");
            }
        }
    }
    fprintf(stderr, "My next seq: %d -- I expect: %d\n", seq_num, expecting_seq);
    //Set socket nonblocking
    int socket_flags = fcntl(sockfd, F_GETFL);
    socket_flags |= O_NONBLOCK;
    fcntl(sockfd, F_SETFL, socket_flags);

    /* Normal State */
    while (true) {
        uint8_t data_buff[MSS]; uint16_t nread;
        char buf[sizeof(packet)] = {0};
        packet* pkt = (packet*) buf;

        // Receiving data
        int bytes_recvd = recvfrom(sockfd, pkt, sizeof(packet),
            0, (struct sockaddr*)addr, &addr_len);

        // TODO: Set Receive Buffer Window
        if(bytes_recvd > 0){
            uint16_t ack = ntohs(pkt->ack);
            uint16_t seq = ntohs(pkt->seq);
            uint16_t length = ntohs(pkt->length);
            bool ack_flag = (pkt->flags);

            // Integrity Check
            if(!verify_parity(pkt)){
                fprintf(stderr, "Dropping Corrupt packet %d\n", seq);
                continue;
            }


            //If ACK flag is set, remove ACKed packets from sending buffer
            if(ack_flag){
                // fprintf(stderr, "Recv ack for %d\n", ack);
                ack_buffer(send_buffer, ack);

                // If dedicated ACK pkt, then continue
                if(length <= 0) continue;
            }

            // Place the packet in receiving buffer
            insert_packet(recv_buffer, (*pkt));

            // Do a linear scan of all the packets in the receiving buffer starting with the next SEQ you expect and write their contents to standard output
            uint16_t next_seq = read_buffer(recv_buffer, output_p);

            // Creating ACK packet
            // ?: Should it ACK just received packet or just outputed?
            packet* ack_pkt = (packet*) buf;
            ack_pkt->flags = 1;
            ack_pkt->ack = htons(next_seq);
            uint16_t input_read = input_p(data_buff, MSS);
            ack_pkt->length = htons(0);
            ack_pkt->seq = htons(0);

            // If there is data to send with ACK, add to buffer
            if(input_read){
                ack_pkt->length = htons(nread);
                memcpy(pkt->payload, data_buff, nread);
                ack_pkt->seq = htons(next_seq);
                insert_packet(send_buffer, (*ack_pkt));
            }
            set_parity_bit(ack_pkt);


            // Send back ACK
            sendto(sockfd, ack_pkt, sizeof(packet) - (MSS-ntohs(ack_pkt->length)),
                    0, (struct sockaddr*)addr, addr_len);
        }


        // Sending Data
        // Send until window is full
        nread = input_p(data_buff, MSS);
        if(nread){
            // TODO: Set Buffer Windows
            if(get_buffer_size(send_buffer) < their_recv_win){

                //Encode packet to send
                packet* pkt = (packet*) buf;
                pkt->seq = htons(seq_num);
                pkt->ack = htons(0);
                memcpy(pkt->payload, data_buff, nread);
                pkt->length = htons(nread);
                pkt->flags = 0;
                pkt->win = MAX_WINDOW;
                set_parity_bit(pkt);

                int did_send = sendto(sockfd, pkt, sizeof(packet) - (MSS-nread),
                0, (struct sockaddr*)addr, addr_len);

                if(did_send>0){
                    // Add packet to sending buffer
                    insert_packet(send_buffer, *pkt);
                    seq_num++;
                }
            }
        }
    }
}


uint16_t get_buffer_size(std::list<packet> buff){
    uint16_t buff_size = 0;

    for (auto const& i : buff) {
        buff_size += ntohs(i.length);
    }

    return buff_size;
}