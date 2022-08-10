#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include <freeipmi/api/ipmi-api.h>
#include <freeipmi/driver/ipmi-openipmi-driver.h>
#include "ipmi-api-defs.h"

#ifdef __UINT8_TYPE__
typedef __UINT8_TYPE__ uint8_t;
#endif

#ifdef __UINT16_TYPE__
typedef __UINT16_TYPE__ uint16_t;
#endif

#ifdef __UINT32_TYPE__
typedef __UINT32_TYPE__ uint32_t;
#endif

/* Project config */
#define PROJ_NAME "FW UPDATE TOOL"
#define PROJ_DESCRIPTION "Firmware update tool from host, including [BIC] [BIOS] [CPLD]."
#define PROJ_VERSION "v1.0.4"
#define PROJ_DATE "2022.04.13"
#define PROJ_AUTH "Quanta"
#define PROJ_LOG_FILE "./log.txt"
int DEBUG_LOG = 0;

/* Firware update size relative config */
#define MAX_IMG_LENGTH 0x2000000
#define MAX_IPMB_SIZE 244
#define MAX_IPMB_DATA_SIZE 224
#define SECTOR_SZ_32M 0x2000000

/* Firware update command relative config(using ipmi-raw) */
#define FW_UPDATE_NETFN 0x38
#define FW_UPDATE_CMD 0x09
#define FW_UPDATE_LUN 0x00
#define PREFIX_IPMI_RAW "./ipmi-raw"
#define IPMI_RAW_RETRY 2

/* QUANTA oem command relative config */
#define OEM_38 0x38
#define OEM_36 0x36
#define IANA_1 0x15
#define IANA_2 0xA0
#define IANA_3 0x00

/* IPMI CC(from yv3.5) */
enum { CC_SUCCESS = 0x00,
       CC_INVALID_PARAM = 0x80,
       CC_FRU_DEV_BUSY = 0x81,
       CC_BRIDGE_MSG_ERR = 0x82,
       CC_I2C_BUS_ERROR = 0x83,
       CC_INVALID_IANA = 0x84,
       CC_NODE_BUSY = 0xC0,
       CC_INVALID_CMD = 0xC1,
       CC_INVALID_LUN = 0xC2,
       CC_TIMEOUT = 0xC3,
       CC_OUT_OF_SPACE = 0xC4,
       CC_INVALID_RESERVATION = 0xC5,
       CC_DATA_TRUNCATED = 0xC6,
       CC_INVALID_LENGTH = 0xC7,
       CC_LENGTH_EXCEEDED = 0xC8,
       CC_PARAM_OUT_OF_RANGE = 0xC9,
       CC_SENSOR_NOT_PRESENT = 0xCB,
       CC_INVALID_DATA_FIELD = 0xCC,
       CC_CAN_NOT_RESPOND = 0xCE,
       CC_NOT_SUPP_IN_CURR_STATE = 0xD5,
       CC_UNSPECIFIED_ERROR = 0xFF,
};

/*
 * IPMI 2.0 Payload is 2 bytes, so we'll assume that size * 2 for good measure.
 * This is from the ipmi-raw head file.
 */
#define IPMI_RAW_MAX_ARGS (65536*2)

typedef enum fw_type {
    FW_T_BIC,
    FW_T_BIOS,
    FW_T_CPLD,
    FW_T_CXL,
    FW_T_MAX_IDX
} fw_type_t;

char *IMG_TYPE_LST[3] = {"BIC", "BIOS", "CPLD", "CXL"};

typedef struct fw_update_data {
    uint8_t target;
    uint8_t offset[4];
    uint8_t length[2];
    uint8_t data[MAX_IPMB_DATA_SIZE];
} fw_update_data_t;

typedef struct ipmi_cmd {
    uint8_t netfn; /* include LUN */
    uint8_t cmd;
    uint8_t data[MAX_IPMB_SIZE];
    uint32_t data_len;
}ipmi_cmd_t;

union ipmi_cmd_uni
{
    ipmi_cmd_t msg;
    char buf[sizeof(ipmi_cmd_t)];
};


typedef enum
{
    LOG_INF = 0x01,
    LOG_DBG = 0x02,
    LOG_WRN = 0x04,
    LOG_ERR = 0x08,
    LOG_NON = 0xff
}LOG_TAG;

const char* plock_file_path = "/var/run/BIC_FW_updating";

/* Function declare */
static void log_print(LOG_TAG level, const char *va_alist, ...);
static void datetime_get(char *psDateTime);
static void log_record(char *file_path, char *content, int init_flag);
static uint32_t read_binary(const char *bin_path, uint8_t *buff, uint32_t buff_len);
static int send_recv_command(ipmi_ctx_t ipmi_ctx, ipmi_cmd_t *msg);
static int do_bic_update(uint8_t *buff, uint32_t buff_len);
static int fw_update(fw_type_t flag, uint8_t *buff, uint32_t buff_len);
static int init_process_lock_file(void);
static int lock_plock_file(int fd);
static int unlock_plock_file(int fd);

/*
  - Name: log_print
  - Description: Print message with header
  - Input:
      * level: Level of message
      * va_alist: Format of message
      * ...: Add args if needed in format
  - Return:
      * none
*/
static void log_print(LOG_TAG level, const char *va_alist, ...)
{
    if (!va_alist)
        return;

    va_list ap;
    switch (level)
    {
    case LOG_INF:
        printf("<system> ");
        break;
    case LOG_DBG:
        printf("<debug>  ");
        break;
    case LOG_WRN:
        printf("<warn>   ");
        break;
    case LOG_ERR:
        printf("<error>  ");
        break;
    default:
        break;
    }
    va_start(ap, va_alist);
    vfprintf(stdout, va_alist, ap);
    va_end(ap);
    return;
}

/*
  - Name: datetime_get
  - Description: Get current timestamp
  - Input:
      * psDateTime: Buffer to read back time string, ex:"2022-04-07 15:43:40"
  - Return:
      * none
*/
static void datetime_get(char *psDateTime)
{
    if (!psDateTime) {
        log_print(LOG_ERR, "%s: Get empty inputs!\n", __func__);
        return;
    }

    time_t nSeconds;
    struct tm *pTM = NULL;

    time(&nSeconds);
    pTM = localtime(&nSeconds);

    sprintf(psDateTime, "%04d-%02d-%02d %02d:%02d:%02d",
            pTM->tm_year + 1900, pTM->tm_mon + 1, pTM->tm_mday,
            pTM->tm_hour, pTM->tm_min, pTM->tm_sec);
}

/*
  - Name: log_record
  - Description: Record log to file
  - Input:
      * file_path: ipmi-raw session
      * content: IPMI package
      * init_flag: 0 if append, 1 if create/rewrite
  - Return:
      * none
*/
static void log_record(char *file_path, char *content, int init_flag)
{
    if (!file_path || !content) {
        log_print(LOG_ERR, "%s: Get empty inputs!\n", __func__);
        return;
    }

    uint32_t content_size = 0;
    char *tmp = content;
    while(*tmp) {
        content_size++;
        tmp++;
    }

    FILE *ptr;
    if (init_flag) {
        ptr = fopen(file_path, "w");
    } else {
        ptr = fopen(file_path, "a");
    }

    if (!ptr) {
        log_print(LOG_ERR, "%s: Invalid log file path [%s]\n", __func__, file_path);
        return;
    }
    log_print(LOG_NON, "%s\n", content);
    char cur_time[22];
    datetime_get(cur_time);

    char output[content_size+22];
    sprintf(output, "[%s] %s", cur_time, content);

    fwrite(output, 1, sizeof(output), ptr);

    fclose(ptr);

    return;
}

/*
  - Name: read_binary
  - Description: Read binary file to buffer
  - Input:
      * bin_path: Binary file path
      * buff: Buffer to read back image bytes
      * buff_len: Buffer length
  - Return:
      * Binary file size, if no error
      * 0, if error
*/
static uint32_t read_binary(const char *bin_path, uint8_t *buff, uint32_t buff_len)
{
    if (!buff || !bin_path) {
        log_print(LOG_ERR, "%s: Get empty inputs!\n", __func__);
        return 0;
    }

    FILE *ptr;
    uint32_t bin_size = 0;

    ptr = fopen(bin_path,"rb");
    if (!ptr) {
        log_print(LOG_ERR, "%s: Invalid bin file path [%s]\n", __func__, bin_path);
        return 0;
    }

    fseek(ptr, 0, SEEK_END);
    bin_size = ftell(ptr);
    fseek(ptr, 0, SEEK_SET);

    if (bin_size > buff_len) {
        log_print(LOG_ERR, "%s: Given buffer length (0x%x) smaller than Image length (0x%x)\n",
            __func__, buff_len, bin_size);
        bin_size = 0;
        goto ending;
    }

    fread(buff, buff_len, 1, ptr);

    if (DEBUG_LOG >= 3) {
        for (int i=0; i<bin_size; i++)
            log_print(LOG_NON, "[0x%x] ", buff[i]);
        log_print(LOG_NON, "\n");
        log_print(LOG_INF, "Image size: 0x%x\n", bin_size);
    }

ending:
    fclose(ptr);
    return bin_size;
}

/*
  - Name: send_recv_command
  - Description: Send and receive message of ipmi-raw
  - Input:
      * ipmi_ctx: ipmi-raw session
      * msg: IPMI package
  - Return:
      * Completion code, if no error
      * -1, if error
*/
static int send_recv_command(ipmi_ctx_t ipmi_ctx, ipmi_cmd_t *msg)
{
    int ret = -1;
    int ipmi_data_len = msg->data_len;
    if (!ipmi_ctx || !msg) {
        log_print(LOG_ERR, "%s: Get empty inputs!\n", __func__);
        return -1;
    }

    if (DEBUG_LOG >= 2) {
        log_print(LOG_NON, "     * ipmi command     : 0x%x/0x%x\n", msg->netfn, msg->cmd);
        log_print(LOG_NON, "     * ipmi data length : %d\n", msg->data_len);
        log_print(LOG_NON, "     * ipmi data        : ");

        /* IPMI data max print limit is 10 */
        int max_data_print = 10;

        if (msg->data_len <= max_data_print)
            max_data_print = msg->data_len;

        for (int i=0; i<max_data_print; i++)
            log_print(LOG_NON, "0x%x ", msg->data[i]);
        log_print(LOG_NON, "...\n");
    }

    int oem_flag = 0;

    if ( (msg->netfn >> 2) == OEM_36 || (msg->netfn >> 2) == OEM_38) {
        ipmi_data_len += 3;
        if (ipmi_data_len > MAX_IPMB_SIZE)
            return -1;
        oem_flag = 1;
    }

    uint8_t *ipmi_data;
    int init_idx = 0;
    ipmi_data = (uint8_t*)malloc(++ipmi_data_len);// Insert one byte from the head.
    if (!ipmi_data) {
        log_print(LOG_ERR, "%s: ipmi_data malloc failed!\n", __func__);
        return -1;
    }
    ipmi_data[0] = msg->cmd;// The byte #0 is cmd.
    init_idx++;
    if (oem_flag) {
        ipmi_data[1] = IANA_1;
        ipmi_data[2] = IANA_2;
        ipmi_data[3] = IANA_3;
        init_idx += 3;
    }
    memcpy(&ipmi_data[4], msg->data, msg->data_len);

    int rs_len = 0;
    uint8_t *bytes_rs = NULL;
    if (!(bytes_rs = calloc (IPMI_RAW_MAX_ARGS, sizeof (uint8_t))))
    {
        log_print(LOG_ERR, "%s: bytes_rs calloc failed!\n", __func__);
        goto ending;
    }

    rs_len = ipmi_cmd_raw(
        ipmi_ctx,
        msg->netfn & 0x03,
        msg->netfn >> 2,
        ipmi_data, //byte #0 = cmd
        ipmi_data_len, // Add 1 because the cmd is combined with the data buf.
        bytes_rs,
        IPMI_RAW_MAX_ARGS
    );

    ret = bytes_rs[1];

    /* Check for ipmi-raw command response */
    if (bytes_rs[0] != msg->cmd || bytes_rs[1] != CC_SUCCESS)
    {
        log_print(LOG_ERR, "%s: ipmi-raw received bad cc 0x%x\n", __func__, bytes_rs[1]);
        goto ending;
    }

    /* Check for oem iana */
    if (oem_flag) {
        if (bytes_rs[2]!=IANA_1 || bytes_rs[3]!=IANA_2 || bytes_rs[4]!=IANA_3) {
            log_print(LOG_ERR, "%s: ipmi-raw received invalid IANA\n", __func__);
            ret = -1;
            goto ending;
        }
    }

ending:
    if (ipmi_data)
        free(ipmi_data);
    if (bytes_rs)
        free(bytes_rs);

    return ret;
}

/*
  - Name: do_bic_update
  - Description: BIC update process
  - Input:
      * buff: Buffer to store image bytes
      * buff_len: Buffer length
  - Return:
      * 0, if no error
      * 1, if error
*/
static int do_bic_update(uint8_t *buff, uint32_t buff_len)
{
    int ret = 1;

    FILE *fp;
    char tx_buf[4096] = {0}, rx_buf[4096] = {0};
    int tail_of_tx_buf = 0;
    union ipmi_cmd_uni msg_uni;
    char debug_ptr = NULL;

    if (!buff) {
        log_print(LOG_ERR, "%s: Get empty inputs!\n", __func__);
        return 1;
    }

    // ipmi_ctx_t ipmi_ctx = ipmi_ctx_create();
    // if (ipmi_ctx == NULL)
    // {
    //     log_print(LOG_ERR, "%s: ipmi_ctx_create error\n", __func__);
    //     return 1;
    // }

    // ipmi_ctx->type = IPMI_DEVICE_OPENIPMI;
    // if (!(ipmi_ctx->io.inband.openipmi_ctx = ipmi_openipmi_ctx_create ()))
    // {
    //     log_print(LOG_ERR, "%s: !(ipmi_ctx->io.inband.openipmi_ctx = ipmi_openipmi_ctx_create ())\n", __func__);
    //     goto clean;
    // }

    // if (ipmi_openipmi_ctx_io_init (ipmi_ctx->io.inband.openipmi_ctx) < 0)
    // {
    //     log_print(LOG_ERR, "%s: ipmi_openipmi_ctx_io_init (ctx->io.inband.openipmi_ctx) < 0\n", __func__);
    //     goto clean;
    // }

    uint32_t cur_msg_offset = 0;
    uint8_t *cur_buff = buff;
    uint8_t last_cmd_flag = 0;
    uint32_t section_offset = 0;
    uint16_t section_idx = 0;
    uint8_t percent;

    uint16_t msg_len;
    if (buff_len > MAX_IPMB_DATA_SIZE) {
        msg_len = MAX_IPMB_DATA_SIZE;
    }else {
        msg_len = buff_len;
        last_cmd_flag = 1;
    }

    while(cur_msg_offset < buff_len) {
        if (section_offset == SECTOR_SZ_32M) {
            section_offset = 0;
            section_idx++;
        }

        /* If current size over 64K */
        if ( (section_offset + MAX_IPMB_DATA_SIZE) / SECTOR_SZ_32M )
            msg_len = (SECTOR_SZ_32M - section_offset);
        else
            msg_len = MAX_IPMB_DATA_SIZE;

        /* If next msg offset over given img length */
        if ( (cur_msg_offset + msg_len) >= buff_len) {
            msg_len = (buff_len - cur_msg_offset);
            last_cmd_flag = 1;
        }

        fw_update_data_t cmd_data;
        if (last_cmd_flag)
            cmd_data.target = 0x80 | FW_T_CXL;
        else
            cmd_data.target = FW_T_CXL;

        cmd_data.offset[0] = (cur_msg_offset & 0xFF);
        cmd_data.offset[1] = (cur_msg_offset >> 8) & 0xFF;
        cmd_data.offset[2] = (cur_msg_offset >> 16) & 0xFF;
        cmd_data.offset[3] = (cur_msg_offset >> 24) & 0xFF;
        cmd_data.length[0] = msg_len & 0xFF;
        cmd_data.length[1] = (msg_len >> 8) & 0xFF;
        memcpy(cmd_data.data, cur_buff, msg_len);

        if ( percent != (cur_msg_offset+msg_len)*100/buff_len ) {
            percent = (cur_msg_offset+msg_len)*100/buff_len;
            if (!(percent % 5))
                log_print(LOG_NON, "         update status %d%%\n", percent);
        }

        ipmi_cmd_t msg_out;
        msg_out.netfn = FW_UPDATE_NETFN << 2;
        msg_out.cmd = FW_UPDATE_CMD;
        msg_out.data_len = msg_len+7;
        memcpy(msg_out.data, &cmd_data, msg_len+7);

        if (DEBUG_LOG >= 1) {
            log_print(LOG_DBG, "section_idx[%d] section_offset[0x%x/0x%x] image_offset[0x%x]\n",
                   section_idx, section_offset, SECTOR_SZ_32M, cur_msg_offset);
            log_print(LOG_NON, "        target[0x%x] offset[0x%x] size[%d]\n",
                    msg_out.data[0],
                    msg_out.data[1]|(msg_out.data[2] << 8)|(msg_out.data[3] << 16)|(msg_out.data[4] << 24),
                    msg_out.data[5]|(msg_out.data[6] << 8));
        }

        // int resp_cc = send_recv_command(ipmi_ctx, &msg_out);
        memcpy(&msg_uni.msg, &msg_out, sizeof(ipmi_cmd_t));

        memset(tx_buf, 0, sizeof(tx_buf));
        memset(rx_buf, 0, sizeof(rx_buf));

        strcpy(tx_buf, "bic-util slot1 0xe0 0x02 0x15 0xa0 0x00 0x05 ");

        for (size_t i = 0; i < sizeof(ipmi_cmd_t); i++)
        {
            tail_of_tx_buf = strlen(tx_buf);
            if (tail_of_tx_buf > sizeof(ipmi_cmd_t))
            {
                printf("tx_buf is overflowed\n");
            }

            sprintf(&tx_buf[tail_of_tx_buf], "0x%2d ", msg_uni.buf[i]);
        }
        tail_of_tx_buf = strlen(tx_buf);
        if (tail_of_tx_buf > sizeof(ipmi_cmd_t))
        {
            printf("tx_buf is overflowed\n");
        }
        sprintf(&tx_buf[tail_of_tx_buf], "\n\0");

        if ((fp = popen( tx_buf, "r")) == NULL) {
            printf("Error: %s", strerror(errno));
            return -1;
        }

        while(fgets(rx_buf, sizeof(rx_buf), fp) != NULL) {
            for (size_t i = 0; i < 7; i++)
            {
                printf("%s ", debug_ptr = strtok(rx_buf, " "));
            }
        }

        pclose(fp);
        if (strcmp(debug_ptr, "00")) {
            log_print(LOG_WRN, "Given update offset not mach with previous record!\n");
            log_print(LOG_NON, "         Retry in few seconds...\n");
            goto clean;
        }

        cur_msg_offset += msg_len;
        cur_buff += msg_len;
        section_offset += msg_len;
    }
    ret = 0;

clean:
    ipmi_ctx_close (ipmi_ctx);
    ipmi_ctx_destroy (ipmi_ctx);
    return ret;
}

/*
  - Name: fw_update
  - Description: Firmware update controller
  - Input:
      * flag: Image type flag
      * buff: The whole image binary data
      * buff_len: whole image binary data length
  - Return:
      * 0, if no error
      * 1, if error
*/
static int fw_update(fw_type_t flag, uint8_t *buff, uint32_t buff_len)
{
    if (!buff) {
        log_print(LOG_ERR, "%s: Get empty inputs!\n", __func__);
        return 1;
    }

    switch(flag)
    {
    case FW_T_CXL:
        int retry = 0;
        while (retry <= IPMI_RAW_RETRY)
        {
            if (retry)
                log_print(LOG_INF, "BIC update retry %d/%d ...\n", retry, IPMI_RAW_RETRY);

            int ret = do_bic_update(buff, buff_len);
            if (!ret)
                break;
            retry++;
        }
        if (retry > IPMI_RAW_RETRY)
            return 1;
        break;
    case FW_T_BIOS:
        log_print(LOG_WRN, "BIOS update hasn't support yet!\n");
        return 1;
        break;
    case FW_T_CPLD:
        log_print(LOG_WRN, "CPLD update hasn't support yet!\n");
        return 1;
        break;
    default:
        log_print(LOG_ERR, "%s: No such flag!\n", __func__);
        return 1;
        break;
    }

    return 0;
}

void HELP()
{
    log_print(LOG_NON, "Try: ./host_fw_update <fw_type> <img_path> <log_level>\n");
    log_print(LOG_NON, "     <fw_type>   Firmware type [0]BIC [1]BIOS [2]CPLD\n");
    log_print(LOG_NON, "     <img_path>  Image path\n");
    log_print(LOG_NON, "     <log_level> (optional) Log level [-v]L1 [-vv]L2 [-vvv]L3\n\n");
}

void HEADER_PRINT()
{
    log_print(LOG_NON, "===============================================================================\n");
    log_print(LOG_NON, "* Name         : %s\n", PROJ_NAME);
    log_print(LOG_NON, "* Description  : %s\n", PROJ_DESCRIPTION);
    log_print(LOG_NON, "* Ver/Date     : %s/%s\n", PROJ_VERSION, PROJ_DATE);
    log_print(LOG_NON, "* Author       : %s\n", PROJ_AUTH);
    log_print(LOG_NON, "* Note         : %s\n", "none");
    log_print(LOG_NON, "===============================================================================\n");
}

int main(int argc, const char** argv)
{
////TEST
    // FILE *fp;
    // char buf[256] = {0};

    // if ((fp = popen("bic-util slot1 0x18 0x01", "r")) == NULL) {
    //     printf("Error: %s", strerror(errno));
    //     return -1;
    // }

    // while(fgets(buf, sizeof(buf), fp) != NULL) {
    //     printf("%s", buf);
    // }

    // pclose(fp);
    // return 0;

    int img_idx = 0;
    const char *img_path = NULL;
    uint8_t *img_buff = NULL;

    HEADER_PRINT();

    if (argc!=3 && argc!=4) {
        HELP();
        goto ending;
    }

    if (argc == 4) {
        if (strstr(argv[3], "-v"))
            DEBUG_LOG = 1;
        if (strstr(argv[3], "-vv"))
            DEBUG_LOG = 2;
        if (strstr(argv[3], "-vvv"))
            DEBUG_LOG = 3;
    }

    img_idx= atoi(argv[1]);
    img_path = argv[2];

    if ( (img_idx >= FW_T_MAX_IDX) || (img_idx < 0) ) {
        log_print(LOG_ERR, "Invalid <fw_type>!\n");
        HELP();
        goto ending;
    }

    if (!DEBUG_LOG)
        log_print(LOG_INF, "Detail ignore...\n");
    else
        log_print(LOG_INF, "Detail leven %d...\n", DEBUG_LOG);

    log_print(LOG_NON, "\n");
    log_print(LOG_INF, "Start [%s] update task with image [%s]\n", IMG_TYPE_LST[img_idx], img_path);

    img_buff = malloc(sizeof(uint8_t) * MAX_IMG_LENGTH);
    if (!img_buff) {
        log_print(LOG_ERR, "img_buff malloc failed!\n");
        goto ending;
    }

    /* STEP1 - Read image */
    log_print(LOG_NON, "\n");
    log_print(LOG_INF, "STEP1. Read image\n");
    uint32_t img_size = read_binary(img_path, img_buff, MAX_IMG_LENGTH);
    if (!img_size) {
        log_print(LOG_NON, "\n");
        log_print(LOG_INF, "Update failed!\n");
        goto ending;
    }
    log_print(LOG_INF, "PASS!\n");

    /* STEP2 - Upload image */
    log_print(LOG_NON, "\n");
    log_print(LOG_INF, "STEP2. Upload image\n");
    if ( fw_update(img_idx, img_buff, img_size) ) {
        log_print(LOG_NON, "\n");
        log_print(LOG_INF, "Update failed!\n");
        goto ending;
    }
    log_print(LOG_INF, "PASS!\n");

    log_print(LOG_NON, "\n");
    log_print(LOG_INF, "Update complete!\n");

ending:
    if (img_buff)
        free(img_buff);

    if (remove(plock_file_path))
    {
        log_print(LOG_ERR,
        "Can't remove %s: %s\n"
        "Please execute this command: \'rm %s\'\n",
        plock_file_path, strerror(errno), plock_file_path);
    }

    return 0;
}
