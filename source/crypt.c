#include <stdio.h> // input/output
#include <unistd.h> // standard symbolic constants and types
#include <sys/socket.h> // socket interface
#include <linux/if_alg.h> // AF_ALG socket family
#include <string.h> // memcpy, strcpy etc

#include "crypt.h"

void int_to_char_array(__u8 *arr, int n, int size)
{
    for (int i = 0; i < size; i++)
    {
        arr[i] = (n >> (i * 8)) & 0xff; // shift offset by i bytes and mask with 0xff to get the byte
    }
    return 0;
}


int set_key(int *sockfd, char *key)
{
    if (setsockopt(*sockfd, SOL_ALG, ALG_SET_KEY, key, 64) == -1)
    {
        return 1;
    }
    return 0;
}

int crypt_init(char *password, int password_len, int sockfd, int op)
{
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "skcipher",
        .salg_name = "xts(aes)"
    };

    if (create_socket(&sockfd))
    {
        perror("socket");
        return 1;
    };

    if (bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)))
    {
        perror("bind");
        return 1;
    }

    char derived_key[32];

    derive_key(password, password_len, derived_key); 

    if (set_key(&sockfd, &derived_key))
    {
        perror("setsockopt");
        close(sockfd);
        return 1;
    }

    int op;

    if (start_operation(&op, &sockfd))
    {
        perror("accept");
        close(sockfd);
        return 1;
    }

    return 0;
}

init_msg(struct msghdr *msg)
{
    char cbuf[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(int) + TWEAK_SIZE)];
    msg->msg_control = cbuf;
    msg->msg_controllen = sizeof(cbuf);
    return 0;
}


void cmsg_encrypt(struct cmsghdr *cmsg, struct msghdr *msg)
{
    cmsg = CMSG_FIRSTHDR(msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(__u32 *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;
    return 0;
}

void cmsg_decrypt(struct cmsghdr *cmsg, struct msghdr *msg)
{
    cmsg = CMSG_FIRSTHDR(msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(__u32 *)CMSG_DATA(cmsg) = ALG_OP_DECRYPT;
    return 0;
}

void set_tweak(struct cmsghdr *cmsg, struct msghdr *msg, __u8 *tweak)
{
    cmsg = CMSG_FIRSTHDR(msg);
    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(TWEAK_SIZE + sizeof(int));
    struct af_alg_iv *aiv = (struct af_alg_iv *)CMSG_DATA(cmsg);
    aiv->ivlen = TWEAK_SIZE;
    memcpy(aiv->iv, tweak, 16);
    return 0;
}

int send_data(__u8 *data, struct msghdr *msg, struct iovec *iov, int *op)
{
    iov->iov_base = data;
    iov->iov_len = BLOCK_SIZE;
    msg->msg_iov = &iov;
    msg->msg_iovlen = 1;
    int ret = sendmsg(*op, msg, 0);
    if (ret == -1)
    {
        return 1;
    }
    return 0;
}

int crypt_encrypt(char *plaintext, int plaintext_len, char *ciphertext, int ciphertext_len, int op)
{
    struct msghdr msg = {0};
    init_msg(&msg);

    struct cmsghdr *cmsg;
    cmsg_encrypt(&msg, cmsg);
    int disk_size = get_disk_size();
    struct iovec iov;
    // loop over all data in disk in CHUNK_SIZE chunks
    for (unsigned int i = 0; i < disk_size; i += CHUNK_SIZE)
    {
        // read a chunk of data
        __u8 data[CHUNK_SIZE];
        int read = read_data(data, CHUNK_SIZE);
        if (read == 1)
        {
            perror("read");
            return 1;
        }
        for (unsigned int j = 0; j < CHUNK_SIZE; j += BLOCK_SIZE)
        {
            // derive tweak
            __u8 tweak[TWEAK_SIZE];
            derive_tweak(tweak, i + j);
            set_tweak(&cmsg, &msg, );
            // encrypt data
            if (send_data(data, &msg, &iov, &op) == 1)
            {
                perror("sendmsg");
                return 1;
            }
        }
    }
    // end loop
    return 0;
}

int crypt_decrypt(char *plaintext, int plaintext_len, char *ciphertext, int ciphertext_len, int op)
{
    struct msghdr msg = {0};
    init_msg(&msg);

    struct cmsghdr *cmsg;
    cmsg_decrypt(&msg, cmsg);
    int disk_size = get_disk_size();
    struct iovec iov;
    // loop over all data in disk in CHUNK_SIZE chunks
    for (unsigned int i = 0; i < disk_size; i += CHUNK_SIZE)
    {
        // read a chunk of data
        __u8 data[CHUNK_SIZE];
        int read = read_data(data, CHUNK_SIZE);
        if (read == 1)
        {
            perror("read");
            return 1;
        }
        for (unsigned int j = 0; j < CHUNK_SIZE; j += BLOCK_SIZE)
        {
            // derive tweak
            __u8 tweak[TWEAK_SIZE];
            derive_tweak(tweak, i + j);
            set_tweak(&cmsg, &msg, );
            // encrypt data
            if (send_data(data, &msg, &iov, &op) == 1)
            {
                perror("sendmsg");
                return 1;
            }
        }
    }
    // end loop
    return 0;
}

int crypt_destroy(int sockfd, int op)
{
    close(op);
    close(sockfd);
    return 0;
}