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

struct sockaddr_in* global_addr;
int global_sockfd;
socklen_t global_addr_len;


uint16_t recv_win = MAX_WINDOW;

// Updates when receiving new packets
uint16_t their_recv_win =  MAX_WINDOW;

uint16_t seq_num = 0;
uint16_t expecting_seq = 0;

std::list<packet> send_buffer;
std::list<packet> recv_buffer;


// Remove acknowledged packets from buffer
void ack_buffer(std::list<packet>& buff, uint16_t ack){
    std::list<packet>::iterator i = send_buffer.begin();
    while(i != send_buffer.end())
    {
        // fprintf(stderr,"SEND BUF %d ", ntohs(i->seq));
        fprintf(stderr,"ENTERING ACK_BUFFER %d\n", ntohs((*i).seq));

        if(ntohs((*i).seq) < ack) {
            fprintf(stderr,"REMOVING SEQ FROM SENDING BUF %d\n", ntohs(i->seq));

            i = buff.erase(i);
        }

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
    fprintf(stderr, "RECV BUFFER ADD %d\n", ntohs(new_packet.seq));
}

// Creates and Sends packet, adds to buffer and returns success
bool send_packet(uint16_t ack, uint16_t flags,
    uint8_t* data_buffer, ssize_t data_len) {

    printf("Creating Packet %d\n", seq_num);
    char buf[sizeof(packet)] = {0};
    packet* pkt = (packet*) buf;

    // Set header fields:
    pkt->seq = (data_len<0 && flags == 0x2) ? htons(0) : htons(seq_num);
    pkt->ack = htons(ack);       // Ack number
    pkt->length = htons(data_len);  // Size of Payload
    pkt->win = htons(512);     // Window size
    pkt->flags = flags;   // Flags: (hex: 0x3 = 110 - SYN=1, ACK=1, Parity=0 )
    pkt->unused = htons(0);    // Unused field

    // Copy the data buffer into the payload (if data_len > 0)
    if (data_len > 0 && data_buffer != nullptr) {
        memcpy(pkt->payload, data_buffer, data_len);
        seq_num++;
    }

    set_parity_bit(pkt);

    int did_send = sendto(global_sockfd, pkt, sizeof(packet) - (MSS-data_len),
    0, (struct sockaddr*)global_addr, global_addr_len);

    if(did_send>0){
        // Add packet to sending buffer
        if (data_len != 0) {
            insert_packet(send_buffer, *pkt);
        }
        fprintf(stderr, "Packet sent: %d\n", seq_num-1);
        return true;
    }
    return false;
}

bool receive_packet(){



    return true;
}

// Output data from buffer and return next expected sequence number
uint16_t read_buffer(std::list<packet>& buff,
                    void (*output_p)(uint8_t*, size_t)){
    std::list<packet>::iterator i = buff.begin();
    while(i != buff.end() )
    {
        fprintf(stderr, "Expecting packet %d , seeing %d\n", expecting_seq, ntohs((*i).seq));

        if(ntohs((*i).seq) == expecting_seq){
            output_p((*i).payload, ntohs((*i).length));
            fprintf(stderr, "RECV BUFF ERASE - SEQ# %d\n",ntohs((*i).seq));
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
    global_addr = addr;
    global_sockfd = sockfd;
    global_addr_len = sizeof(struct sockaddr_in);
    socklen_t addr_len = sizeof(struct sockaddr_in);

    /* Perform 3-Way Handshake */
    if(type == SERVER) {
        srand(time(0));
        uint8_t server_recv_handshake_buffer[sizeof(packet)] = {0};
        packet* server_recv_pkt = (packet*) server_recv_handshake_buffer;

        uint8_t server_send_handshake_buffer[sizeof(packet)] = {0};

        // 1. Receive client SYN
        int bytes_recvd = recvfrom(sockfd, server_recv_pkt, sizeof(packet),
            0, (struct sockaddr*)addr, &addr_len);
        if(bytes_recvd < 0 ) {
           perror("Error receiving client SYN");
        }

        expecting_seq = htons(server_recv_pkt->seq);

        // Output data if there is a payload
        if(htons(server_recv_pkt->length) > 0){
            insert_packet(recv_buffer, (*server_recv_pkt));
            read_buffer(recv_buffer, output_p);
        }

        fprintf(stderr, "Client seq: %d received, flags=%d\n", htons(server_recv_pkt->seq), server_recv_pkt->flags);

        // 2. Send back SYN ACK

        // Equivalent: char ack[] = "ACK 457, SEQ 789, SYN, ACK";
        uint16_t ack = htons(server_recv_pkt->seq) + 1, flags = 0x3;
        // 0x3 = 011 - PARITY=0, SYN=1, ACK=1
        seq_num = rand() % 1000;
        //Check if need to send with a payload
        //Encode packet to send

        char buf[sizeof(packet)] = {0};
        packet* pkt = (packet*) buf;
        pkt->seq = htons(seq_num);
        pkt->flags = flags;
        pkt->win = htons(MAX_WINDOW);
        pkt->ack = htons(ack);

        uint8_t data_buff[MSS];
        uint16_t nread = input_p(data_buff, MSS);
        pkt->length = htons(nread);
        memcpy(pkt->payload, data_buff, nread);
        set_parity_bit(pkt);

        // make_handshake_packet(server_send_handshake_buffer, nullptr, 0, seq_num, ack, flags);

        // // set parity
        // packet* server_send_pkt = (packet*) server_send_handshake_buffer;

        if(bytes_recvd > 0){ // TODO: This should check for SYN ACK details
            int did_send = sendto(sockfd, pkt, sizeof(packet), 0, (struct sockaddr*)addr, addr_len);
            if(did_send) {
                fprintf(stderr, "sent server SYN ACK Seq:%d, ACK: %d\n", seq_num, ack);
                expecting_seq = ack;
                seq_num ++;
            }
        }

        // 3. Receive last ACK
        // bytes_recvd = recvfrom(sockfd, server_recv_pkt, sizeof(packet),
        //     0, (struct sockaddr*)addr, &addr_len);

        // if(bytes_recvd > 0){
        //     if(htons(server_recv_pkt->length) != 0){
        //         fprintf(stderr, "Data from last client ACK\n");

        //         expecting_seq = htons(server_recv_pkt->seq) ;
        //     }

        // //     fprintf(stderr, "Client seq: %d received, flags=%d\n", htons(server_recv_pkt->seq), server_recv_pkt->flags);
        // }
    }


    if(type == CLIENT){
        srand(time(0)+1);

        // 1. Send first SYN with random SEQ
        uint8_t client_send_buffer[sizeof(packet)] = {0};
        packet* client_send_pkt = (packet*) client_send_buffer;
        uint8_t client_recv_handshake_buffer[sizeof(packet)] = {0};
        packet* client_recv_pkt = (packet*) client_recv_handshake_buffer;

        // char syn_buff[] = "SYN SEQ= random: 1-1000";
        uint16_t ack = 0, flags = 0x1;
        seq_num = rand() % 1000 ; // 0x1 = 001 - PARITY=0, SYN=0, ACK=1

        //Check if need to send with a payload
        //Encode packet to send
        client_send_pkt->seq = htons(seq_num);
        client_send_pkt->flags = flags;
        client_send_pkt->win = htons(MAX_WINDOW);
        client_send_pkt->ack = htons(ack);

        uint8_t data_buff[MSS];
        uint16_t nread = input_p(data_buff, MSS);
        client_send_pkt->length = htons(nread);
        memcpy(client_send_pkt->payload, data_buff, nread);
        set_parity_bit(client_send_pkt);

        // make_handshake_packet(client_send_handshake_buffer, nullptr, 0, seq_num, ack, flags);

        int did_send = sendto(sockfd, client_send_pkt, sizeof(packet) - (MSS-nread),
            0, (struct sockaddr*)addr, addr_len);

        if(did_send){
            fprintf(stderr, "sent first client SYN -- seq: %d: \n", ntohs(client_send_pkt->seq));
            seq_num++;
        }

        // 2. Receive SYN ACK from Server
        int bytes_recvd = recvfrom(sockfd, client_recv_pkt, sizeof(packet), 0, (struct sockaddr*)addr, &addr_len);

        if (bytes_recvd > 0){
            packet* client_recv_pkt = (packet*) client_recv_handshake_buffer;
            fprintf(stderr, "Server seq: %d received, flags=%d\n", htons(client_recv_pkt->seq), client_recv_pkt->flags);

            // char syn_ack_buff[] = "ACK 790, SEQ 457, ACK";
            ack = htons(client_recv_pkt->seq) + 1, flags = 0x2; // 0x1 = 010 - PARITY=0, ACK=1, SYN=0
            expecting_seq = htons(client_recv_pkt->seq);

            //Check if there is payload
            if(htons(client_recv_pkt->length) > 0){
                insert_packet(recv_buffer, (*client_recv_pkt));
                read_buffer(recv_buffer, output_p);
            }


            // 3. Send final ACK back to server
            // Check if need to send with data
            nread = input_p(data_buff, MSS);

            uint16_t next_seq_num = (nread) ? seq_num : 0;
            client_send_pkt->win = htons(MAX_WINDOW);
            make_handshake_packet(client_send_buffer, data_buff, nread, next_seq_num, ack, flags);

            // Data was sent, update sequence number and add to sending buffer
            if(next_seq_num) {
                seq_num++;
            }

            // set parity
            set_parity_bit(client_send_pkt);

            sendto(sockfd, client_send_pkt, sizeof(packet) - (MSS-nread),
            0, (struct sockaddr*)addr, addr_len);

            if(did_send) {
                fprintf(stderr, "sent last client SYN - seq= %d\n", ntohs(client_send_pkt->seq));
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
            bool ack_flag = (pkt->flags >> 1) & 1;

            fprintf(stderr, "Received packet %d - Length:%d\n", seq, length);

            // Integrity Check
            if(!verify_parity(pkt)){
                fprintf(stderr, "Dropping Corrupt packet %d\n", seq);
                continue;
            }

            //If ACK flag is set, remove ACKed packets from sending buffer
            if(ack_flag){
                fprintf(stderr, "Recv ack for %d\n", ack);
                ack_buffer(send_buffer, ack);

                // If dedicated ACK pkt, then continue
                if(length <= 0) continue;
            }

            // Place the packet in receiving buffer
            insert_packet(recv_buffer, (*pkt));

            // Do a linear scan of all the packets in the receiving buffer starting with the next SEQ you expect and write their contents to standard output
            uint16_t next_seq = read_buffer(recv_buffer, output_p);

            nread = input_p(data_buff, MSS);
            // Send back ACK packet of next expected sequence
            bool did_send = send_packet(next_seq, 0x2, data_buff, nread);
            if(did_send){
                fprintf(stderr, "Sent ACK  %d\n", next_seq);
            }
        }

        // Sending Data
        // Send until window is full
        nread = input_p(data_buff, MSS);
        if(nread){
            // TODO: Set Buffer Windows
            if(get_buffer_size(send_buffer) < their_recv_win){

                bool did_send = send_packet(0,0, data_buff, nread);
                if(did_send){
                    fprintf(stderr, "Sent Packet: %d\n", seq_num-1);
                }
            }
        }
    }
}


uint16_t get_buffer_size(std::list<packet> buff){
    uint16_t buff_size = 0;

    for (auto const& i : buff) {
        fprintf(stderr,"SEND BUF %d",ntohs(i.seq));
        buff_size += ntohs(i.length);
    }
    fprintf(stderr,"\n");

    return buff_size;
}