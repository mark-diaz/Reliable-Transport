# CS 118 Winter 25 Project 1
This is a semi-reliable transport protocol built on UDP for CS 118.


#### **Design Choices**:
- We use the std::list data structure to hold our receiving and sending buffer because it made inserting and traversing fairly simple
- We also decided to modularize a lot of the functions like `insert_packet()` for operations on the sending and receiving buffer so that we could write cleaner code and debug easier
- We also chose to modify the packet struct so that it contains an array instead of a pointer to avoid dynamic memory allocations

**Listen Loop**: 
- We distinguish the client and server in the handshake but generalizing in the normal state
- Our listen loop first checks for received packets and sends data piggy-backed on the acks 
- If there is not any data to receive then we send data that is not piggy-backed on an ack

#### **Problems and Solutions**
1. We struggled to synchronize sequence numbers between sender and receiver, especially when deciding exactly when to increment. 
- To fix this, we made sure to only bump the sequence counter after sending real data (not pure ACKs), keeping both endpoints aligned.

2. Dealing with out of order packets. 
- To solve this, we inserted each incoming packet into a sorted buffer, then released them in ascending order based on sequence number, ensuring no data was skipped or repeated.

3. Overwhelming the server - resulted in dropped packets without letting the client know
- We didn't really completely solve this but we prevented it in most of the cases by checking if recv_window minus our current in flight packets (`get_buffer_size(send_buffer)`) is greater than the size of the packet we are going to send.
