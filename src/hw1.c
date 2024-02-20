#include "hw1.h"
#include <stdint.h>


//part 1

void print_packet_sf(unsigned char packet[])
{   
    (void)packet;
    //missing 3rd byte of destination address
    uint32_t src_address = ((uint32_t)packet[0] << 20) | ((uint32_t)packet[1] << 12) | ((uint32_t)packet[2] << 4) | ((uint32_t)packet[3] >> 4);
    uint32_t dest_address = (((uint32_t)packet[3])& 0x0f) << 24|((uint32_t)packet[4] << 16) | ((uint32_t)packet[5] << 8) | ((uint32_t)packet[6]);
    uint8_t src_port = (uint32_t)packet[7] >>4;
    uint8_t dest_port = (uint8_t)packet[7] & ~0xf0;
    uint16_t frag_offset = ((uint16_t)packet[8] << 6) | ((uint16_t)packet[9] >> 2) ;
    uint16_t packet_len = (((uint16_t)packet[9] & 0x03) << 12) | (uint16_t)packet[10] << 4 | (uint16_t)packet[11]>>4;
    uint8_t max_hc = ((uint8_t)packet[11] & 0x0f) << 1 | (uint8_t)packet[12] >> 7;
    uint32_t checksum = ((uint32_t)packet[12] & ~0x80) <<16 | (u_int32_t)packet[13] <<8 | (uint32_t)packet[14];
    uint8_t comp_scheme = (uint8_t)packet[15] >> 6;
    uint8_t traffic_class = (uint8_t)packet[15] & ~0xc0;

    
    
    printf("Source Address: %d\nDestination Address: %d\nSource Port: %d\nDestination Port: %d\nFragment Offset: %d\nPacket Length: %d\nMaximum Hop Count: %d\nChecksum: %d\nCompression Scheme: %d\nTraffic Class: %d\nPayload: ", src_address, dest_address, src_port, dest_port, frag_offset, packet_len, max_hc, checksum, comp_scheme, traffic_class);

    for (int i = 16; i < packet_len-4; i += 4) {
        int32_t payload_value = ((int32_t)packet[i] << 24) |
                                ((int32_t)packet[i + 1] << 16) |
                                ((int32_t)packet[i + 2] << 8) |
                                (int32_t)packet[i + 3];
        printf("%d ", payload_value);
        
    }
    int32_t last_payload_value = ((int32_t)packet[packet_len-4] << 24) |
                                 ((int32_t)packet[packet_len -3] << 16) |
                                 ((int32_t)packet[packet_len-2] << 8) |
                                 (int32_t)packet[packet_len -1];

    printf("%d\n", last_payload_value);
}








//part 2
unsigned int compute_checksum_sf(unsigned char packet[])
{
    (void)packet;

    unsigned int src_address = ((unsigned int )packet[0] << 20) | ((unsigned int )packet[1] << 12) | ((unsigned int )packet[2] << 4) | ((unsigned int )packet[3] >> 4);
    unsigned int  dest_address = (((unsigned int)packet[3])& 0x0f) << 24|((unsigned int )packet[4] << 16) | ((unsigned int )packet[5] << 8) | ((unsigned int )packet[6]);
    unsigned int  src_port = (unsigned int )packet[7] >>4;
    unsigned int  dest_port = (unsigned int )packet[7] & ~0xf0;
    unsigned int  frag_offset = ((unsigned int )packet[8] << 6) | ((unsigned int )packet[9] >> 2) ;
    unsigned int  packet_len = (((unsigned int )packet[9] & 0x03) << 12) | (unsigned int )packet[10] << 4 | (unsigned int )packet[11]>>4;
    unsigned int  max_hc = ((unsigned int )packet[11] & 0x0f) << 1 | (unsigned int )packet[12] >> 7;
    // printf("frag offset debug %x %x, %x %x, %u\n", packet[8], packet[9],  ((unsigned int )packet[8] << 6), ((unsigned int )packet[9] >> 2), frag_offset);
    unsigned int  comp_scheme = (unsigned int )packet[15] >> 6;
    unsigned int  traffic_class = (unsigned int )packet[15] & ~0xc0;

    unsigned int sumfields = src_address + dest_address + src_port + dest_port + frag_offset + packet_len + max_hc + comp_scheme + traffic_class;
    // printf("%u %u %u %u %u %u %u %u %u\n", src_address, dest_address, src_port, dest_port, frag_offset, packet_len, max_hc, comp_scheme, traffic_class);
    //printf("Sum of fields: %u\n", sumfields);
    unsigned int sumpayloads = 0;

    for (int i = 16; i < packet_len-4; i += 4) {
        int32_t payload_value = ((unsigned int )packet[i] << 24) |
                                ((unsigned int )packet[i + 1] << 16) |
                                ((unsigned int )packet[i + 2] << 8) |
                                (unsigned int )packet[i + 3];
        sumpayloads += abs(payload_value);
        // printf("Payload value: %d\n", payload_value);
        // printf("Sum of payloads so far: %u\n", sumpayloads);
        
    }
    int32_t last_payload_value = ((unsigned int )packet[packet_len-4] << 24) |
                                 ((unsigned int) packet[packet_len -3] << 16) |
                                 ((unsigned int )packet[packet_len-2] << 8) |
                                 (unsigned int )packet[packet_len -1];
    sumpayloads += abs(last_payload_value);
    
    // printf("Payload value: %d\n", last_payload_value);
    //printf("Sum of payloads so far: %u\n", sumpayloads);

    //given a packet and complete except for checksum, compute and return the packet's checksum.
     
    unsigned int checksum = sumfields + sumpayloads;
    //printf("Checksum total is %u\n", checksum);
    
   // printf("Final checksum is %u\n", checksum % ((1u << 23)-1));
    return checksum % ((1u << 23)-1);

    //step one: calculate all the fields
    //step two: calculate the sum of the absolute values of the integers in the payload
    //step three: divide these by 2^23 -1
    

}


//part 3
unsigned int reconstruct_array_sf(unsigned char *packets[], unsigned int packets_len, int *array, unsigned int array_len) {
    unsigned int counter = 0;

    for(unsigned int i = 0; i < packets_len; i++) {
        unsigned char *packet = packets[i];
        uint32_t actualChecksum = ((uint32_t)packet[12] & ~0x80) << 16 | (uint32_t)packet[13] << 8 | (uint32_t)packet[14];
        
        if(compute_checksum_sf(packet) != actualChecksum) {
        } else {
            uint16_t packet_len = (((uint16_t)packet[9] & 0x03) << 12) | (uint16_t)packet[10] << 4 | (uint16_t)packet[11] >> 4;
            uint16_t frag_offset = ((uint16_t)packet[8] << 6) | ((uint16_t)packet[9] >> 2);
            unsigned int start_index = frag_offset / sizeof(int);
            unsigned int j = start_index;
            
            for (unsigned int k = 16; k < packet_len; k += 4) {
                int32_t payload_value = ((int32_t)packet[k] << 24) |
                                        ((int32_t)packet[k + 1] << 16) |
                                        ((int32_t)packet[k + 2] << 8) |
                                        (int32_t)packet[k + 3];
                if(j < array_len) {
                    array[j++] = payload_value; 
                    counter+= 1;
                }
            }
            
        }
    }

    return counter;
}

//part 4
unsigned int packetize_array_sf(int *array, unsigned int array_len, unsigned char *packets[], unsigned int packets_len,
                          unsigned int max_payload, unsigned int src_addr, unsigned int dest_addr,
                          unsigned int src_port, unsigned int dest_port, unsigned int maximum_hop_count,
                          unsigned int compression_scheme, unsigned int traffic_class)
{
    (void)array; //array: the array of signed 32-bit integers to packetize
    (void)array_len; //array_len: the number of elements in array
    (void)packets;//an array of char * pointers. store the packets in this
    (void)packets_len;//the number of elements (pointers) in the packets array.
    (void)max_payload;// the maximum payload size of any packet created and referenced by packets.
    (void)src_addr;// source address
    (void)dest_addr;//destination address
    (void)src_port;
    (void)dest_port;
    (void)maximum_hop_count; //the integer to be stored in the packets which represents the maximum number of hops these packets may take
    (void)compression_scheme;//the integer to store in the packets which represents the compression algorithm used to compress the payload.
    (void)traffic_class;    
     

    unsigned int start = 0;
    unsigned int payload_len = 0;
    unsigned int num_packets = (array_len / (max_payload/sizeof(int))) +1; //correct
    //don't exceed capacity of array
    if(num_packets > packets_len){
        num_packets = packets_len;
    }


    for(unsigned int i = 0; i < num_packets; i++){
        //calculate payload length for packet
        if(max_payload/sizeof(int)<=array_len-start){
            payload_len = (max_payload/sizeof(int));
        }else{
            payload_len = array_len - start;
        }


        unsigned int frag_offset = start * sizeof(int);
        unsigned int packet_len = 16 + payload_len*sizeof(int);

        packets[i] = malloc(packet_len);

        for (unsigned int o= 0; o<packet_len; o++){
            packets[i][o] = 0;
        }
        

       packets[i][0] = (src_addr >> 20) & 0xff;
       packets[i][1] = (src_addr >> 12) & 0xff;
       packets[i][2] = (src_addr >> 4) & 0xff;
       packets[i][3] = (src_addr & 0xf) << 4 | (dest_addr >> 24) & 0x0f; 
       packets[i][4] = (dest_addr >> 16) & 0xff;
       packets[i][5] = (dest_addr >> 8) & 0xff;
       packets[i][6] = (dest_addr) & 0xff;
       packets[i][7] = (src_port <<4) & 0xff | dest_port & 0xff;
       packets[i][8] = (frag_offset >> 6) & 0xff;
       packets[i][9] = (frag_offset << 2) & 0xff | (packet_len >> 12) & 0x03;
       packets[i][10]= (packet_len >> 4) & 0xff;
       packets[i][11] = (packet_len & 0x0f) << 4 | (maximum_hop_count >> 1) & 0xff;
       packets[i][15] = (compression_scheme << 6) & 0xff| (traffic_class & 0xff);

    //calculate payload:
        int packet_index = 16; // Start index for placing values in packet
        //num_values = size of array
        for (int x = start; x < start + payload_len; x++) {
        int32_t payload_value = array[x];
        
        // Convert payload_value into bytes and place them in packet
        packets[i][packet_index++] = (payload_value >> 24) & 0xFF;
        packets[i][packet_index++] = (payload_value >> 16) & 0xFF;
        packets[i][packet_index++] = (payload_value >> 8) & 0xFF;
        packets[i][packet_index++] = payload_value & 0xFF;
        }

        packets[i][12] = ((maximum_hop_count & 0x01) << 7);
        unsigned int checksum = compute_checksum_sf(packets[i]);
        packets[i][12] |=  ((checksum >> 16) & 0x7f);
        packets[i][13] = (checksum >> 8) & 0xff;
        packets[i][14] = checksum & 0xff;
        
        start += payload_len;
    }
    
    return num_packets;
    

}
