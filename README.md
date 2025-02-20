# CS 118 Winter 25 Project 1
Our transport layer implementation builds on top of the UDP protocol to provide a reliable, in-order data transfer. Initially, we use a three-way handshake mechanism to ensure both sides are aware of each other’s initial sequence numbers before transmitting any real data.

Once the handshake is completed, each side continuously reads from its standard input and sends data packets with a minimum segment size of 1012 bytes. Each packet’s header contains a sequence number and acknowledgment number, allowing for us to use cumulative ACKs. The receiver stores out-of-order packets in a linked list and only writes them to stdout once it has the correct in-order sequence.

To handle packet loss or corruption, we use duplicate ACKs and a retransmission timer. If the sender sees the same ACK value three times in a row, it retransmits the oldest unacknowledged packet. If the retransmission timer runs out before we recieve a new ACK, we can retransmit. We also use a parity bit in the header of each packet to detect single-bit errors. If there is a mismatch on the receiver's end, the packet is discarded.

Furthermore, our implementation has a "send buffer" of packets that have not been ACKed, which are then removed from said buffer when they are eventually ACKed. Finally, we ensure that we do not overload the receiver's flow window by tracking and updating the window size with each packet sent.

We initially struggled to synchronize sequence numbers between sender and receiver, especially when deciding exactly when to increment. To fix this, we made sure to only bump the sequence counter after sending real data (not pure ACKs), keeping both endpoints aligned.

Another issue we ran into was dealing with out of order packets. To solve this, we inserted each incoming packet into a sorted buffer, then released them in ascending order based on sequence number, ensuring no data was skipped or repeated.
