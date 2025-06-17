// UDP_Communication_Framework.cpp : Defines the entry point for the console application.
//

#pragma comment(lib, "ws2_32.lib")
#include "stdafx.h"
#include <winsock2.h>
#include "ws2tcpip.h"
#include <string>
#include <fstream>
#include <iostream>
#include<windows.h>
#include <cstdint>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


/* Auxiliary functions for MD5 */
#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))

/* Rotate left macro definition */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static void MD5Transform(uint32_t state[4], const unsigned char block[64]);
static void Encode(unsigned char* output, const uint32_t* input, unsigned int len);
static void Decode(uint32_t* output, const unsigned char* input, unsigned int len);

static const unsigned char PADDING[64] = {
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

typedef struct {
    uint32_t state[4];   /* state (ABCD) */
    uint32_t count[2];   /* number of bits, modulo 2^64 (lsb first) */
    unsigned char buffer[64];   /* input buffer */
} MD5_CTX;

static void MD5Init(MD5_CTX* context) {
    context->count[0] = context->count[1] = 0;
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

static void MD5Update(MD5_CTX* context, const unsigned char* input, unsigned int inputLen) {
    unsigned int i, index, partLen;
    index = (unsigned int)((context->count[0] >> 3) & 0x3F);
    if ((context->count[0] += ((uint32_t)inputLen << 3)) < ((uint32_t)inputLen << 3))
        context->count[1]++;
    context->count[1] += ((uint32_t)inputLen >> 29);
    partLen = 64 - index;
    if (inputLen >= partLen) {
        memcpy(&context->buffer[index], input, partLen);
        MD5Transform(context->state, context->buffer);
        for (i = partLen; i + 63 < inputLen; i += 64)
            MD5Transform(context->state, &input[i]);
        index = 0;
    }
    else
        i = 0;
    memcpy(&context->buffer[index], &input[i], inputLen - i);
}

static void MD5Final(unsigned char digest[16], MD5_CTX* context) {
    unsigned char bits[8];
    unsigned int index, padLen;
    Encode(bits, context->count, 8);
    index = (unsigned int)((context->count[0] >> 3) & 0x3F);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    MD5Update(context, PADDING, padLen);
    MD5Update(context, bits, 8);
    Encode(digest, context->state, 16);
    memset(context, 0, sizeof(*context));
}
static void Decode(uint32_t* output, const unsigned char* input, unsigned int len) {
    unsigned int i, j;
    for (i = 0, j = 0; j < len; i++, j += 4)
        output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j + 1]) << 8) |
                    (((uint32_t)input[j + 2]) << 16) | (((uint32_t)input[j + 3]) << 24);
}
static void Encode(unsigned char* output, const uint32_t* input, unsigned int len) {
    unsigned int i, j;
    for (i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = (unsigned char)(input[i] & 0xff);
        output[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
        output[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
        output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);
    }
}

/* MD5 basic transformation. Transforms state based on block. */
static void MD5Transform(uint32_t state[4], const unsigned char block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    Decode(x, block, 64);
    /* Round 1 */
    FF(a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
    FF(d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
    FF(c, d, a, b, x[2], S13, 0x242070db); /* 3 */
    FF(b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
    FF(a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
    FF(d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
    FF(c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
    FF(b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
    FF(a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
    FF(d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
    FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
    FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
    FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
    FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
    FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
    FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */
    /* Round 2 */
    GG(a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
    GG(d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
    GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
    GG(b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
    GG(a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
    GG(d, a, b, c, x[10], S22, 0x2441453);  /* 22 */
    GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
    GG(b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
    GG(a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
    GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
    GG(c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */
    GG(b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
    GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
    GG(d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
    GG(c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */
    /* Round 3 */
    HH(a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
    HH(d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
    HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
    HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
    HH(a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
    HH(d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
    HH(c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
    HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
    HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
    HH(d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
    HH(c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
    HH(b, c, d, a, x[6], S34, 0x4881d05);  /* 44 */
    HH(a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
    HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
    HH(b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */
    /* Round 4 */
    II(a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
    II(d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
    II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
    II(b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
    II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
    II(d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
    II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
    II(b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
    II(a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
    II(c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
    II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
    II(a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
    II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
    II(c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
    II(b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    memset(x, 0, sizeof x);
}
#define TARGET_IP	"127.0.0.1"

#define BUFFERS_LEN 1024
#define DATA_LEN 1016
#define NUMBER_LEN 4
#define CRC_LEN 4
#define WINDOW_LENGTH 20

#define SENDER
//#define RECEIVER

#ifdef SENDER
#define TARGET_PORT 5412
#define LOCAL_PORT 5478
#endif // SENDER

#ifdef RECEIVER
#define TARGET_PORT 5190
#define LOCAL_PORT 5324
#endif // RECEIVER


void InitWinsock()
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}
uint32_t crc32(const void* data, size_t n_bytes) {
    uint32_t crc = 0xFFFFFFFF;
    static uint32_t table[256];

    // Generov�n� tabulky pro CRC
    if (table[1] == 0) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (size_t j = 0; j < 8; j++) {
                c = c & 1 ? (c >> 1) ^ 0xEDB88320 : c >> 1;
            }
            table[i] = c;
        }
    }

    for (size_t i = 0; i < n_bytes; i++) {
        crc = table[(crc ^ ((const uint8_t*)data)[i]) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}
// false if not in list
bool isInList(uint32_t* ListOfUints, uint32_t number, size_t length) {
    for (int i = 0; i < length; i++) {
        if (ListOfUints[i] == number) {
            return true;
        }
    }
    return false;
}
//returns false if there is no such number
bool replaceInList(uint32_t* ListOfUints, uint32_t numberReplaced, uint32_t numberReplacor, size_t length) {
    for (int i = 0; i < length; i++) {
        if (ListOfUints[i] == numberReplaced) {
            ListOfUints[i] = numberReplacor;
            return true;
        }
    }
    return false;
}

bool addToListCycle(uint32_t* ListOfUints, uint32_t number, size_t length, size_t* index) {
    ListOfUints[*index] = number;
    (*index)++;
    if (*index >= length) {
        *index = 0;
    }
    return true;
}

bool processReceivedPacket(SOCKET socketS, char* buffer_rx, int data_len, FILE* fp, sockaddr_in from, sockaddr_in addrDest, int& packetIndex, char* lastBuffer, uint32_t* last_packet_number, int size, uint32_t packetsBefore) {
    uint32_t received_crc;
    memcpy(&received_crc, buffer_rx + data_len, sizeof(received_crc)); // Extrahujeme CRC z p�ijat�ho bufferu
    uint32_t calculated_crc = crc32(buffer_rx, data_len); // Vypo��t�me CRC z dat
    uint32_t current_packet_number;
    memcpy(&current_packet_number, buffer_rx, sizeof(current_packet_number));
    char* sizechar = "size";
    char ack[10];

    if (received_crc == calculated_crc) {
        printf("Packet number %d expected\n", packetIndex);
        printf("Packet number %d received \n", current_packet_number);
        if (packetIndex == -1)
        {
            int lastLen = size % (data_len - sizeof(uint32_t));
            printf("%d", lastLen);
            size_t offset = packetsBefore - 1 * DATA_LEN;
            fseek(fp, offset, SEEK_SET);
            fwrite(buffer_rx + sizeof(uint32_t), 1, lastLen * sizeof(char), fp);
            printf("Packet number %d received correctly.\n", packetIndex);
            sendto(socketS, "ACK", 3, 0, (sockaddr*)&addrDest, sizeof(addrDest));
            memcpy(lastBuffer, buffer_rx, BUFFERS_LEN); // Odes?l?me ACK
            return true;
        }
        else {
            memset(buffer_rx, 0, BUFFERS_LEN);
            memcpy(ack, "ACK", 3);
            memcpy(buffer_rx, ack, sizeof(ack));
            memcpy(buffer_rx + sizeof(ack), &current_packet_number, sizeof(current_packet_number));
            calculated_crc = crc32(buffer_rx, sizeof(current_packet_number) + sizeof(ack));
            memcpy(buffer_rx + sizeof(current_packet_number) + sizeof(ack), &calculated_crc, sizeof(calculated_crc));
            sendto(socketS, buffer_rx, sizeof(current_packet_number) + sizeof(ack) + sizeof(calculated_crc), 0, (sockaddr*)&addrDest, sizeof(addrDest));
            return true;
        }
    }
}
bool processReceivedPackets(SOCKET socketS, char* buffer_rx, int data_len, FILE* fp, sockaddr_in from, sockaddr_in addrDest, char* lastBuffer, uint32_t* last_packet_number, int size, int& fromlen) {
    uint32_t received_crc;
    uint32_t calculated_crc; // Vypo��t�me CRC z dat
    uint32_t current_packet_number;
    uint32_t currentlyRecieved[WINDOW_LENGTH];
    size_t currentlyRecievedLength = WINDOW_LENGTH;
    uint32_t LastTenTimesRecieved[WINDOW_LENGTH * 10];
    size_t LastTenTimesRecievedLength = WINDOW_LENGTH * 10;
    LastTenTimesRecieved[0] = 0;
    size_t indexInTenTimes = 1;
    size_t indexInRecieved = 0;
    char ack[10];



    char* sizechar = "size";
    while (true) {
        for (size_t i = 0; i < WINDOW_LENGTH; i++)
        {
            bool newPacket = false;
            memset(buffer_rx, 0, BUFFERS_LEN);
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(socketS, &read_fds);
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 5000; //2 ms
            int selectResult = select(socketS + 1, &read_fds, NULL, NULL, &tv);
            if (selectResult > 0) {
                recvfrom(socketS, buffer_rx, BUFFERS_LEN, 0, (sockaddr*)&from, &fromlen);
                memcpy(&received_crc, buffer_rx + data_len, sizeof(received_crc)); // Extrahujeme CRC z p�ijat�ho bufferu
                calculated_crc = crc32(buffer_rx, data_len);
                memcpy(&current_packet_number, buffer_rx, sizeof(current_packet_number));
                if ((received_crc == calculated_crc) && isInList(LastTenTimesRecieved, current_packet_number, LastTenTimesRecievedLength)) {
                    printf("Duplicate packet number %d received, sending ACK only.\n", current_packet_number);
                    currentlyRecieved[i] = current_packet_number;
                    indexInRecieved++;
                }
                else if (received_crc == calculated_crc) {
                    printf("Packet number %d received \n", current_packet_number);
                    currentlyRecieved[i] = current_packet_number;
                    indexInRecieved++;
                    addToListCycle(LastTenTimesRecieved, current_packet_number, LastTenTimesRecievedLength, &indexInTenTimes);
                    size_t offset = currentlyRecieved[i] * DATA_LEN;
                    fseek(fp, offset, SEEK_SET);
                    fwrite(buffer_rx + sizeof(uint32_t), 1, data_len - sizeof(uint32_t), fp);
                }
                else {
                    // mozna poslat nack nebo ignorovat a pak poslat znovu?
                }
            }
            else {
                // nic nepřišlo
            }
        }
        for (size_t i = 0; i < WINDOW_LENGTH; i++) {
            if (i < indexInRecieved) {
                memset(buffer_rx, 0, BUFFERS_LEN);
                memcpy(ack, "ACK", 3);
                memcpy(buffer_rx, ack, sizeof(ack));
                memcpy(buffer_rx + sizeof(ack), &currentlyRecieved[i], sizeof(currentlyRecieved[i]));
                calculated_crc = crc32(buffer_rx, sizeof(currentlyRecieved[i]) + sizeof(ack));
                memcpy(buffer_rx + sizeof(currentlyRecieved[i]) + sizeof(ack), &calculated_crc, sizeof(calculated_crc));
                sendto(socketS, buffer_rx, sizeof(currentlyRecieved[i]) + sizeof(ack) + sizeof(calculated_crc), 0, (sockaddr*)&addrDest, sizeof(addrDest));
                Sleep(2);
            }
            else {
                Sleep(2);
            }
        }
        indexInRecieved = 0;
    }
}
void sendLastDataPacket(SOCKET socketS, char* buffer_tx, int ata_len, sockaddr_in addrDest, sockaddr_in& from, int& fromlen, FILE* file, uint32_t packet_number, uint32_t number_for_read, uint32_t size) {
    char ack[10];
    //int readLen = data_len - sizeof(uint32_t);
    // �ten� dat ze souboru a v�po�et CRC
    size_t offset = number_for_read * DATA_LEN;
    fseek(file, offset, SEEK_SET);
    fread(buffer_tx + sizeof(uint32_t), sizeof(char), size % DATA_LEN, file);
    memcpy(buffer_tx, &packet_number, sizeof(packet_number));
    uint32_t crc_value = crc32(buffer_tx, DATA_LEN + NUMBER_LEN);
    memcpy(buffer_tx + DATA_LEN + NUMBER_LEN, &crc_value, sizeof(crc_value));
    printf("number sent %d\n", packet_number);
    int num_of_whiles = 0;
    // Opakov�n� odesl�n� dokud neobdr��me "ACK"
    do {
        if (packet_number == -1) {
            num_of_whiles++;
            if (num_of_whiles == 10) {
                printf("assuming lost ACK ftom last package");
                break;
            }
        }
        sendto(socketS, buffer_tx, DATA_LEN + NUMBER_LEN + CRC_LEN, 0, (sockaddr*)&addrDest, sizeof(addrDest));
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(socketS, &read_fds);
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        int selectResult = select(socketS + 1, &read_fds, NULL, NULL, &tv);
        if (selectResult > 0) {
            memset(ack, 0, sizeof(ack));
            recvfrom(socketS, ack, sizeof(ack), 0, (sockaddr*)&from, &fromlen);
            printf("Received %s\n", ack);
        }
        else if (selectResult == 0) {
            printf("Timeout, no ACK received. Resending packet.\n");
            continue;
        }
    } while (!(strncmp(ack, "ACK", 3) == 0));
}
void sendFirstDataPacket(SOCKET socketS, char* buffer_tx, int ata_len, sockaddr_in addrDest, sockaddr_in& from, int& fromlen, FILE* file, uint32_t packet_number) {
    char ack[10];
    //int readLen = data_len - sizeof(uint32_t);
    // ?ten? dat ze souboru a v?po?et CRC
    fread(buffer_tx + sizeof(uint32_t), sizeof(char), DATA_LEN, file);
    memcpy(buffer_tx, &packet_number, sizeof(packet_number));
    uint32_t crc_value = crc32(buffer_tx, DATA_LEN + NUMBER_LEN);
    memcpy(buffer_tx + DATA_LEN + NUMBER_LEN, &crc_value, sizeof(crc_value));
    printf("number sent %d\n", packet_number);
    // Opakov?n? odesl?n? dokud neobdr??me "ACK"
    do {
        sendto(socketS, buffer_tx, DATA_LEN + NUMBER_LEN + CRC_LEN, 0, (sockaddr*)&addrDest, sizeof(addrDest));
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(socketS, &read_fds);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        int selectResult = select(socketS + 1, &read_fds, NULL, NULL, &tv);
        if (selectResult > 0) {
            memset(ack, 0, sizeof(ack));
            recvfrom(socketS, ack, sizeof(ack), 0, (sockaddr*)&from, &fromlen);
            printf("Received %s\n", ack);
        }
        else if (selectResult == 0) {
            printf("Timeout, no ACK received. Resending first packet.\n");
            continue;
        }
    } while (!(strncmp(ack, "ACK", 3) == 0));
}
bool sendDataPackets(SOCKET socketS, char* buffer_tx, int ata_len, sockaddr_in addrDest, sockaddr_in& from, int& fromlen, FILE* file, uint32_t packets) {
    packets--; // protoze plnime od 0 ale realne prvni paket neni 0
    char ack[10];
    uint32_t ListOfSending[WINDOW_LENGTH];
    size_t actualSizeOfSendingList = 0;
    size_t sent = WINDOW_LENGTH;
    int index_in_first_list = 0;
    bool control = false;
    const int maxLengthOfThisFucker = packets;
    uint32_t ListOfSent[1];
    for (size_t i = 1; i < WINDOW_LENGTH + 1; i++)
    {
        ListOfSending[index_in_first_list] = i;
        printf("%d in first list", i);
        actualSizeOfSendingList++;
        index_in_first_list++;
    }
    while (true)
    {
        for (size_t i = 0; i < WINDOW_LENGTH; i++)
        {
            if (ListOfSending[i] != 0) {
                memset(buffer_tx, 0, BUFFERS_LEN);
                long offset = ListOfSending[i] * DATA_LEN;
                printf("%d offset", offset);
                fseek(file, offset, SEEK_SET);
                fread(buffer_tx + NUMBER_LEN, sizeof(char), DATA_LEN, file);
                memcpy(buffer_tx, &ListOfSending[i], sizeof(uint32_t));
                uint32_t crc_value = crc32(buffer_tx, DATA_LEN + NUMBER_LEN);
                memcpy(buffer_tx + DATA_LEN + NUMBER_LEN, &crc_value, sizeof(crc_value));
                printf("number sent %d\n", ListOfSending[i]);
                sendto(socketS, buffer_tx, DATA_LEN + NUMBER_LEN + CRC_LEN, 0, (sockaddr*)&addrDest, sizeof(addrDest));
                Sleep(10);
            }
        }

        for (size_t i = 0; i < WINDOW_LENGTH; i++)
        {
            if (ListOfSending[i] != 0) {
                memset(buffer_tx, 0, BUFFERS_LEN);
                /**/fd_set read_fds;
                FD_ZERO(&read_fds);
                FD_SET(socketS, &read_fds);
                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = 5000; //95 ms
                int selectResult = select(socketS + 1, &read_fds, NULL, NULL, &tv);
                if (selectResult > 0) {
                    recvfrom(socketS, buffer_tx, sizeof(ack) + sizeof(uint32_t) + sizeof(uint32_t), 0, (sockaddr*)&from, &fromlen);
                    uint32_t received_crc;
                    memcpy(&received_crc, buffer_tx + sizeof(ack) + sizeof(uint32_t), sizeof(received_crc)); // Extrahujeme CRC z p�ijat�ho bufferu
                    uint32_t calculated_crc = crc32(buffer_tx, sizeof(ack) + sizeof(uint32_t)); // Vypo��t�me CRC z dat
                    uint32_t current_packet_number;
                    memcpy(&current_packet_number, buffer_tx + sizeof(ack), sizeof(current_packet_number));
                    memcpy(&ack, buffer_tx, sizeof(ack));
                    if ((strncmp(ack, "ACK", 3) == 0) && (received_crc == calculated_crc))
                    {
                        printf("Received ACK for package %d \n", current_packet_number);

                        for (size_t k = 0; k < WINDOW_LENGTH; k++)
                        {
                            if (ListOfSending[k] == current_packet_number && sent <= packets-1)
                            {
                                sent++;
                                ListOfSending[k] = sent;
                                control = true;
                                printf("odbaveno %d prislo\n", current_packet_number);

                            }
                            else if (ListOfSending[k] == current_packet_number) {
                                ListOfSending[k] = 0;
                                size_t numOfNuls = 0;
                                control = true;
                                for (size_t j = 0; j < WINDOW_LENGTH; j++)
                                {
                                    if (ListOfSending[j] == 0)
                                    {
                                        numOfNuls++;
                                    }
                                    if (numOfNuls == WINDOW_LENGTH)
                                    {
                                        printf("DOPOSLANO\n");
                                        return true;
                                        break;
                                    }
                                }
                            }
                        }
                        if (!control) {
                            printf("ITS BROKEN SEM TO DOJIT NEMELO%d prislo\n", current_packet_number);
                        }
                        control = false;

                    }
                    else {
                        char acks[4];
                        memset(&acks, 0, 4);
                        memcpy(&acks, ack, 3);

                        printf("%s recieved or wrong CRC\n", acks);
                    }

                }
                else if (selectResult == 0) {
                    printf("Timeout, no ACK received for packet %d.\n", ListOfSending[i]);
                    continue;
                }
            }
        }
    }
}
void sendTextPacket(SOCKET socketS, char* buffer_tx, sockaddr_in addrDest, sockaddr_in& from, int& fromlen, int data_len, char* text) {
    char ack[10];
    uint32_t crc_value = crc32(buffer_tx, data_len);
    memcpy(buffer_tx + data_len, &crc_value, sizeof(crc_value));

    // Odesl�n� dat a �ek�n� na "ACK"
    do {
        sendto(socketS, buffer_tx, data_len + sizeof(crc_value), 0, (sockaddr*)&addrDest, sizeof(addrDest));
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(socketS, &read_fds);
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        int selectResult = select(socketS + 1, &read_fds, NULL, NULL, &tv);
        if (selectResult > 0) {
            memset(ack, 0, sizeof(ack));
            recvfrom(socketS, ack, sizeof(ack), 0, (sockaddr*)&from, &fromlen);
            printf("here Received %s\n", ack);
        }
        else if (selectResult == 0) {
            printf("Timeout, no ACK received. Resending packet.\n");
            continue;
        }
    } while (!(memcmp(ack, "ACK", 3) == 0)); // Opakov�n� odesl�n�, pokud p�ijde "NACK"
}
void fillBuffer(FILE* fp, char* buffer, uint32_t packetNum) {
    size_t offset = packetNum * DATA_LEN;
    fseek(fp, offset, SEEK_SET);


}
void compute_md5(FILE* file, unsigned char digest[16]) {
    MD5_CTX context;
    int bytes;
    unsigned char data[1024];

    MD5Init(&context);

    // �te soubor po ��stech do bufferu a aktualizuje MD5 kontext
    while ((bytes = fread(data, 1, 1024, file)) != 0) {
        MD5Update(&context, data, bytes);
    }

    // Ukon�en� v�po�tu a z�sk�n� fin�ln�ho hash
    MD5Final(digest, &context);

    // Resetov�n� ukazatele souboru na za��tek
    fseek(file, 0, SEEK_SET);
}

//**********************************************************************
int main()
{
    SOCKET socketS;

    InitWinsock();

    struct sockaddr_in local;
    struct sockaddr_in from;

    int fromlen = sizeof(from);
    local.sin_family = AF_INET;
    local.sin_port = htons(LOCAL_PORT);
    local.sin_addr.s_addr = INADDR_ANY;


    socketS = socket(AF_INET, SOCK_DGRAM, 0);
    if (bind(socketS, (sockaddr*)&local, sizeof(local)) != 0) {
        printf("Binding error!\n");
        getchar(); //wait for press Enter
        return 1;
    }
    //**********************************************************************
    char buffer_rx[BUFFERS_LEN];
    char buffer_tx[BUFFERS_LEN];
    int data_len = BUFFERS_LEN - sizeof(uint32_t);
    unsigned char digest[16];

#ifdef SENDER
    sockaddr_in addrDest;
    addrDest.sin_family = AF_INET;
    addrDest.sin_port = htons(TARGET_PORT);
    InetPton(AF_INET, _T(TARGET_IP), &addrDest.sin_addr.s_addr);
    char ack[10];
    uint32_t crc_value;

    char filename[50];
    printf("zadejte nazev souboru\n");
    scanf("%50s", &filename);
    printf("%s\n", filename);
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: File not opened!\n");
        return 1;
    }
    compute_md5(file, digest);
    printf("Hash of file is: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");


    fseek(file, 0, SEEK_END);
    int size = ftell(file);
    fseek(file, 0, SEEK_SET);
    printf("size is %d\n", size);

    strncpy(buffer_tx, "", BUFFERS_LEN);
    char* name = "name";
    printf("Sending packet with name.\n");
    strncpy(buffer_tx + sizeof(name), filename, data_len - sizeof(name));
    strncpy(buffer_tx, name, sizeof(name));
    sendTextPacket(socketS, buffer_tx, addrDest, from, fromlen, data_len, "name");
    printf("packet send\n");
    printf("Sending packet with Hash.\n");
    strncpy(buffer_tx, "", BUFFERS_LEN);
    char* hash = "hash";
    memcpy(buffer_tx + sizeof(hash), digest, data_len - sizeof(hash));
    strncpy(buffer_tx, hash, sizeof(hash));
    sendTextPacket(socketS, buffer_tx, addrDest, from, fromlen, data_len, "hash");
    printf("packet send\n");

    char* sizechar = "size";
    strncpy(buffer_tx, "", BUFFERS_LEN);
    memcpy(buffer_tx + sizeof(sizechar), &size, data_len - sizeof(sizechar));
    strncpy(buffer_tx, sizechar, sizeof(sizechar));
    printf("Sending packet with size.\n");
    sendTextPacket(socketS, buffer_tx, addrDest, from, fromlen, data_len, "size");

    sendFirstDataPacket(socketS, buffer_tx, data_len, addrDest, from, fromlen, file, 0);
    int num_of_packets = size / DATA_LEN;
    strncpy(buffer_tx, "", BUFFERS_LEN);
    Sleep(100);
    sendDataPackets(socketS, buffer_tx, data_len, addrDest, from, fromlen, file, num_of_packets);

    Sleep(50 * WINDOW_LENGTH + 100 * WINDOW_LENGTH * 10);
    if (size % data_len != 0) {
        //upravit tady pozici fp
        strncpy(buffer_tx, "", BUFFERS_LEN);
        sendLastDataPacket(socketS, buffer_tx, data_len, addrDest, from, fromlen, file, -1, num_of_packets, size);
        printf("Packet the rest.\n");
    }


    fclose(file);
    closesocket(socketS);
#endif // SENDER

#ifdef RECEIVER
    sockaddr_in addrDest;
    addrDest.sin_family = AF_INET;
    addrDest.sin_port = htons(TARGET_PORT);
    InetPton(AF_INET, _T(TARGET_IP), &addrDest.sin_addr.s_addr);
    char lastBuffer[BUFFERS_LEN];
    uint32_t last_packet_number = 999;
    uint32_t received_crc, calculated_crc;
    memset(buffer_rx, 0, BUFFERS_LEN);
    memset(lastBuffer, 0, BUFFERS_LEN);
    printf("Waiting for filename and size ...\n");
    char* name = "name";
    if (recvfrom(socketS, buffer_rx, sizeof(buffer_rx), 0, (sockaddr*)&from, &fromlen) == SOCKET_ERROR) {
        printf("Socket error!\n");
        getchar();
        return 1;
    }
    else
    {
        char* name = "name";
        bool success = false;
        while (!success) {
            uint32_t received_crc;
            memcpy(&received_crc, buffer_rx + data_len, sizeof(received_crc)); // Extrahujeme CRC z p�ijat�ho bufferu
            uint32_t calculated_crc = crc32(buffer_rx, data_len); // Vypo��t�me CRC z dat

            if (received_crc == calculated_crc) {
                sendto(socketS, "ACK", 3, 0, (sockaddr*)&addrDest, sizeof(addrDest)); // Odes?l?me ACK
                printf("Packet NAME  received correctly.\n");
                success = true;
            }
            else {
                printf("CRC error in NAME packet number %d. Requesting retransmission.\n", 1);
                sendto(socketS, "NACK", 4, 0, (sockaddr*)&addrDest, sizeof(addrDest)); // Odes?l?me NACK
                recvfrom(socketS, buffer_rx, sizeof(buffer_rx), 0, (sockaddr*)&from, &fromlen);
            }
        }
        printf("File name '%s'\n", buffer_rx + sizeof(name));
    }
    memcpy(lastBuffer, buffer_rx, BUFFERS_LEN);
    printf("File name '%s'\n", lastBuffer);
    char filename[16];
    strncpy(filename, buffer_rx + sizeof(name), 49);
    FILE* fp = fopen(buffer_rx + sizeof(name), "wb");

    if (fp == NULL) {
        printf("Open file error!\n");
        getchar();
        return 1;
    }
    //hash
    bool success = false;
    char* hash = "hash";
    do {
        memset(buffer_rx, 0, BUFFERS_LEN);
        recvfrom(socketS, buffer_rx, sizeof(buffer_rx), 0, (sockaddr*)&from, &fromlen);
        if ((memcmp(hash, buffer_rx, sizeof(hash)) == 0)) {
            success = true;
            printf("NOT SAME PACK.\n");
        }
        else {
            success = false;
        }
        memcpy(&received_crc, buffer_rx + data_len, sizeof(received_crc));
        calculated_crc = crc32(buffer_rx, data_len);
        memset(lastBuffer, 0, BUFFERS_LEN);
        memcpy(lastBuffer, buffer_rx, sizeof(buffer_rx));
        if (received_crc == calculated_crc) {
            printf("Packet HASH  received correctly.\n");

            sendto(socketS, "ACK", 3, 0, (sockaddr*)&addrDest, sizeof(addrDest));
        }
        else
        {
            sendto(socketS, "NACK", 4, 0, (sockaddr*)&addrDest, sizeof(addrDest));
            printf("Packet HASH  received NOT correctly.\n");

        }
    } while ((!(received_crc == calculated_crc)) || !success);
    printf("Hash of recieved file is: ");
    //printf("File name '%s'\n", lastBuffer);
    char recieved_hash[50];
    memcpy(recieved_hash, buffer_rx + sizeof(hash), 50);
    for (int i = 0; i < 16; i++) {
        printf("%02hhx", recieved_hash[i]);
    }
    printf("\n");
    success = false;
    char* sizechar = "size";
    do {
        memset(buffer_rx, 0, BUFFERS_LEN);
        recvfrom(socketS, buffer_rx, sizeof(buffer_rx), 0, (sockaddr*)&from, &fromlen);
        if ((memcmp(sizechar, buffer_rx, sizeof(sizechar)) == 0)) {
            success = true;
            printf("NOT SAME PACK.\n");
        }
        memcpy(&received_crc, buffer_rx + data_len, sizeof(received_crc));
        memset(lastBuffer, 0, BUFFERS_LEN);
        memcpy(&lastBuffer, buffer_rx, sizeof(buffer_rx) - sizeof(received_crc));
        calculated_crc = crc32(buffer_rx, data_len);
        if (received_crc == calculated_crc) {
            printf("Packet number  received correctly.\n");
            sendto(socketS, "ACK", 3, 0, (sockaddr*)&addrDest, sizeof(addrDest));
        }
        else
        {
            sendto(socketS, "NACK", 4, 0, (sockaddr*)&addrDest, sizeof(addrDest));
            printf("Packet number  received NOT correctly.\n");

        }
    } while ((!(received_crc == calculated_crc)) || !success);

    //printf("File name '%s'\n", lastBuffer);


    int size;
    memcpy(&size, buffer_rx + sizeof(sizechar), sizeof(int));

    int packet_num = size / (data_len - sizeof(uint32_t));

    printf("File size %d\n", size);
    printf("Number of packets size %d\n", packet_num);

    printf("Receiveing data...\n");
    success = false;
    do {
        memset(buffer_rx, 0, BUFFERS_LEN);
        recvfrom(socketS, buffer_rx, BUFFERS_LEN, 0, (sockaddr*)&from, &fromlen);
        memcpy(&received_crc, buffer_rx + data_len, sizeof(received_crc));
        calculated_crc = crc32(buffer_rx, data_len);
        if (!(memcmp(sizechar, buffer_rx, sizeof(sizechar)) == 0) && received_crc == calculated_crc) {
            printf("Packet first received correctly.\n");
            fwrite(buffer_rx + sizeof(uint32_t), 1, data_len - sizeof(uint32_t) * sizeof(char), fp);
            success = true;
        }
        if (received_crc == calculated_crc) {
            sendto(socketS, "ACK", 3, 0, (sockaddr*)&addrDest, sizeof(addrDest));
        }
        else
        {
            sendto(socketS, "NACK", 4, 0, (sockaddr*)&addrDest, sizeof(addrDest));
            printf("Packet first  received NOT correctly.\n");
        }
    } while (!success);
    memset(buffer_rx, 0, BUFFERS_LEN);
    processReceivedPackets(socketS, buffer_rx, data_len, fp, from, addrDest, lastBuffer, &last_packet_number, size, fromlen);

    for (int i = 0; i < 1;)
    {
        //upravit pozici FP
        int lol = -1;
        memset(buffer_rx, 0, BUFFERS_LEN);
        recvfrom(socketS, buffer_rx, BUFFERS_LEN, 0, (sockaddr*)&from, &fromlen);
        bool success = processReceivedPacket(socketS, buffer_rx, data_len, fp, from, addrDest, lol, lastBuffer, &last_packet_number, size, packet_num);
        if (success)
        {
            i++;
        }
    }

    fclose(fp);
    printf("All data recieved\n");
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: File not opened!\n");
        return 1;
    }
    compute_md5(file, digest);
    printf("Hash of recieved file is: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", digest[i]);
    }
    if (memcmp((char*)digest, recieved_hash, 16) == 0) {
        printf("Hash is same");
    }
    else {
        printf("Hash is not same");
    }
    fclose(fp);
    closesocket(socketS);
#endif
    //**********************************************************************



    getchar(); //wait for press Enter
    return 0;
}