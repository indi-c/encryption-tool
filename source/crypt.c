#include <stdio.h> // input/output
#include <unistd.h> // standard symbolic constants and types
#include <sys/socket.h> // socket interface
#include <linux/if_alg.h> // AF_ALG socket family
#include <string.h> // memcpy, strcpy etc
#include <stdlib.h> // malloc, free
#include <sys/ioctl.h> // disk size
#include <linux/fs.h> // disk size
#include <fcntl.h> // file control

#include "crypt.h"
#include "kdf.h"

void int_to_char_array(__u8 *arr, int n, int size)
{
    for (int i = 0; i < size; i++)
    {
        arr[i] = (n >> (i * 8)) & 0xff; // shift offset by i bytes and mask with 0xff to get the byte
    }
}

int create_socket(int *sockfd)
{
    *sockfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (*sockfd == -1)
    {
        return 1;
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

int start_operation(int *op, int *sockfd)
{
    *op = accept(*sockfd, NULL, 0);
    if (*op == -1)
    {
        return 1;
    }
    return 0;
}

void get_set_op(int **op, int option)
{
    static int *stored_op;
    if (option == SETTER)
    {
        stored_op = *op;
    }
    else if (option == GETTER)
    {
        // stored_op invalid here
        *op = stored_op;
    }
}

void get_set_sockfd(int **sockfd, int option)
{
    static int *stored_sockfd;
    if (option == SETTER)
    {
        stored_sockfd = *sockfd;
    }
    else if (option == GETTER)
    {
        *sockfd = stored_sockfd;
    }
}

int crypt_init(char *password, int password_len)
{
    static int sockfd;
    static int op;

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

    char *derived_key = malloc(64);

    derive_key(password, password_len, derived_key); 

    if (set_key(&sockfd, derived_key))
    {
        perror("setsockopt");
        close(sockfd);
        return 1;
    }

    if (start_operation(&op, &sockfd))
    {
        perror("accept");
        close(sockfd);
        return 1;
    }

    free(derived_key);
    int *op_ptr = &op;
    int *sockfd_ptr = &sockfd;
    get_set_op(&op_ptr, SETTER);
    get_set_sockfd(&sockfd_ptr, SETTER);
    return 0;
}

int init_msg(struct msghdr **msg)
{
    static char cbuf[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(int) + TWEAK_SIZE)];
    (*msg)->msg_name = NULL;
    (*msg)->msg_namelen = 0;
    (*msg)->msg_control = cbuf;
    (*msg)->msg_controllen = sizeof(cbuf);
    return 0;
}


void cmsg_encrypt(struct cmsghdr **cmsg, struct msghdr *msg)
{
    *cmsg = CMSG_FIRSTHDR(msg);
    (*cmsg)->cmsg_level = SOL_ALG;
    (*cmsg)->cmsg_type = ALG_SET_OP;
    (*cmsg)->cmsg_len = CMSG_LEN(sizeof(int));
    *(__u32 *)CMSG_DATA(*cmsg) = ALG_OP_ENCRYPT;
}

void cmsg_decrypt(struct cmsghdr **cmsg, struct msghdr *msg)
{
    *cmsg = CMSG_FIRSTHDR(msg);
    (*cmsg)->cmsg_level = SOL_ALG;
    (*cmsg)->cmsg_type = ALG_SET_OP;
    (*cmsg)->cmsg_len = CMSG_LEN(sizeof(int));
    *(__u32 *)CMSG_DATA(*cmsg) = ALG_OP_DECRYPT;
}

void set_tweak(struct cmsghdr **cmsg, struct msghdr *msg, __u8 *tweak)
{
    *cmsg = CMSG_FIRSTHDR(msg);
    *cmsg = CMSG_NXTHDR(msg, *cmsg);
    (*cmsg)->cmsg_level = SOL_ALG; // failure point
    (*cmsg)->cmsg_type = ALG_SET_IV;
    (*cmsg)->cmsg_len = CMSG_LEN(TWEAK_SIZE + sizeof(int));
    struct af_alg_iv *aiv = (struct af_alg_iv *)CMSG_DATA(*cmsg);
    aiv->ivlen = TWEAK_SIZE;
    memcpy(aiv->iv, tweak, 16);
}

int send_data(__u8 *data, struct msghdr *msg, struct iovec *iov, int *op)
{
    iov->iov_base = data;
    iov->iov_len = CHUNK_SIZE;
    msg->msg_iov = iov;
    msg->msg_iovlen = 1;
    int ret = sendmsg(*op, msg, 0);
    if (ret == -1)
    {
        return 1;
    }
    return 0;
}

int open_disk(char *diskpath, int *fd)
{
    *fd = open(diskpath, O_RDWR);
    if (*fd == -1)
    {
        return 1;
    }
    return 0;
}

int get_disk_size(int *fd, unsigned long long *disk_size)
{
    if (ioctl(*fd, BLKGETSIZE64, disk_size) == -1) // gets disk size in bytes from file descriptor
    {
        return 1;
    }
    return 0;
}

int read_data(int *fd, __u8 *data)
{
    int bytes_read = read(*fd, data, CHUNK_SIZE);
    if (bytes_read == -1)
    {
        return 1;
    }
    if (bytes_read == 0)
    {
        return 0;
    }
    return bytes_read;
}

int read_result(int *op, __u8 *data)
{
    if (read(*op, data, CHUNK_SIZE) == -1)
    {
        return 1;
    }
    return 0;
}

int write_data(int *fd, __u8 *data)
{
    if (write(*fd, data, CHUNK_SIZE) == -1)
    {
        return 1;
    }
    return 0;
}

void derive_tweak(__u8 *tweak, unsigned long long n)
{
    int_to_char_array(tweak, n, 4);
    memset(tweak + 4, 0, 12);
}

int crypt_encrypt(char *diskpath)
{
    struct msghdr msg = {0};
    struct msghdr *msg_ptr = &msg;
    init_msg(&msg_ptr);

    struct cmsghdr *cmsg;
    cmsg_encrypt(&cmsg, &msg);

    int fd;
    int *op;

    get_set_op(&op, GETTER);
    
    unsigned long long disk_size;

    open_disk(diskpath, &fd);
     
    if (get_disk_size(&fd, &disk_size))
    {
        perror("ioctl");
        return 1;
    }
    
    __u8 *data = malloc(CHUNK_SIZE);
    
    struct iovec iov;
    // loop over all data in disk in CHUNK_SIZE chunks
    for (unsigned long long i = 0; i < disk_size; i += CHUNK_SIZE)
    {
        // read a chunk of data
        int read = read_data(&fd, data);
        
        if (read == 1)
        {
            perror("read");
            return 1;
        }

        if (read == 0)
        {
            break;
        }

        if (read < CHUNK_SIZE)
        {
            memset(data + read, CHUNK_SIZE - read, CHUNK_SIZE - read);
        }

        // derive tweak and set tweak
        __u8 tweak[TWEAK_SIZE];
        derive_tweak(tweak, i);
        
        set_tweak(&cmsg, &msg, tweak);
        // encrypt data
        if (send_data(data, &msg, &iov, op) == 1)
        {
            perror("sendmsg");
            return 1;
        }
        // read ciphertext
        if (read_result(op, data) == 1)
        {
            perror("read");
            return 1;
        }

        // write ciphertext to disk
        if (write_data(&fd, data) == 1)
        {
            perror("write");
            return 1;
        }
    }
    close(fd);
    return 0;
}

int depad(__u8 **data_ptr)
{
    __u8 *data = *data_ptr;
    int pad = data[CHUNK_SIZE - 1];
    for (int i = 0; i < pad; i++)
    {
        if (data[CHUNK_SIZE - 1 - i] != pad)
        {
            return 0;
        }
    }
    __u8 *new_data = realloc(data, CHUNK_SIZE - pad);
    if (new_data == NULL)
    {
        return 1;
    }
    *data_ptr = new_data;
    return 0;
}

int crypt_decrypt(char *diskpath)
{
    struct msghdr msg = {0};
    struct msghdr *msg_ptr = &msg;
    init_msg(&msg_ptr);


    struct cmsghdr *cmsg;
    cmsg_decrypt(&cmsg, &msg);


    int fd;
    int *op;

    get_set_op(&op, GETTER);

    unsigned long long disk_size;

    open_disk(diskpath, &fd);

    if (get_disk_size(&fd, &disk_size))
    {
        perror("ioctl");
        return 1;
    }

    __u8 *data = malloc(CHUNK_SIZE);

    struct iovec iov;
    // loop over all data in disk in CHUNK_SIZE chunks
    for (unsigned long long i = 0; i < disk_size; i += CHUNK_SIZE)
    {
        // read a chunk of data
        int read = read_data(&fd, data);

        if (read == 1)
        {
            perror("read");
            return 1;
        }

        if (read == 0)
        {
            break;
        }

        if (read < CHUNK_SIZE)
        {
            memset(data + read, CHUNK_SIZE - read, CHUNK_SIZE - read);
        }

        // derive tweak and set tweak
        __u8 tweak[TWEAK_SIZE];
        derive_tweak(tweak, i);
        set_tweak(&cmsg, &msg, tweak);

        // encrypt data
        if (send_data(data, &msg, &iov, op) == 1)
        {
            perror("sendmsg");
            return 1;
        }
        // read ciphertext
        if (read_result(op, data) == 1)
        {
            perror("read");
            return 1;
        }

        // depad data
        if (depad(&data) == 1)
        {
            perror("realloc");
            return 1;
        }

        // write ciphertext to disk
        if (write_data(&fd, data) == 1)
        {
            perror("write");
            return 1;
        }
    }
    close(fd);
    return 0;
}

int crypt_destroy()
{
    int *op;
    int *sockfd;
    get_set_op(&op, GETTER);
    get_set_sockfd(&sockfd, GETTER);
    close(*op);
    close(*sockfd);
    return 0;
}