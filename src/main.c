#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <freeipmi/api/ipmi-api.h>
#include <freeipmi/driver/ipmi-openipmi-driver.h>
#include "../includes/ipmi-api-defs.h"

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
#define PROJ_VERSION "v1.0.2"
#define PROJ_DATE "2022.04.07"
#define PROJ_AUTH "Quanta"
#define PROJ_LOG_FILE "./log.txt"

/* Firware update size relative config */
#define MAX_IMG_LENGTH 0x80000
#define MAX_IPMB_SIZE 244
#define MAX_IPMB_DATA_SIZE 224
#define SECTOR_SZ_64K 0x10000

/* Firware update command relative config(using ipmi-raw) */
#define FW_UPDATE_NETFN 0x38
#define FW_UPDATE_CMD 0x09
#define FW_UPDATE_LUN 0x00
#define PREFIX_IPMI_RAW "./ipmi-raw"
#define IPMI_RAW_RETRY 2

/* QUANTA oem command relative config */
#define OEM_38 0x38
#define OEM_36 0x36
#define IANA_1 0x9C
#define IANA_2 0x9C
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

int DEBUG_LOG = 0;

typedef enum fw_type {
    FW_T_BIC,
    FW_T_BIOS,
    FW_T_CPLD,
    FW_T_MAX_IDX
} fw_type_t;

char *IMG_TYPE_LST[3] = {"BIC", "BIOS", "CPLD"};

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

/*
  - Name: datetime_get
  - Description: Get current timestamp
  - Input:
      * psDateTime: Buffer to read back time string, ex:"2022-04-07 15:43:40"
  - Return:
      * none
*/
void datetime_get(char *psDateTime)
{
    if (!psDateTime) {
        printf("<error> datetime_get: Get empty inputs!\n");
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
void log_record(char *file_path, char *content, int init_flag) {
    if (!file_path || !content) {
        printf("<error> log_record: Get empty inputs!\n");
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
        printf("<error> log_record: Invalid log file path [%s]\n", file_path);
        return;
    }
    printf("%s\n", content);
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
uint32_t read_binary(const char *bin_path, uint8_t *buff, uint32_t buff_len) {
    if (!buff || !bin_path) {
        printf("<error> read_binary: Get empty inputs!\n");
        return 0;
    }

    FILE *ptr;
    uint32_t bin_size = 0;

    ptr = fopen(bin_path,"rb");
    if (!ptr) {
        printf("<error> read_binary: Invalid bin file path [%s]\n", bin_path);
        return 0;
    }

    fseek(ptr, 0, SEEK_END);
    bin_size = ftell(ptr);
    fseek(ptr, 0, SEEK_SET);

    if (bin_size > buff_len) {
        printf("<error> read_binary: Given buffer length (0x%x) smaller than Image length (0x%x)\n",
               buff_len, bin_size);
        bin_size = 0;
        goto ending;
    }

    fread(buff, buff_len, 1, ptr);

    if (DEBUG_LOG >= 3) {
        for (int i=0; i<bin_size; i++)
            printf("[0x%x] ", buff[i]);
        printf("\n");
        printf("<system> Image size: 0x%x\n", bin_size);
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
int send_recv_command(ipmi_ctx_t ipmi_ctx, ipmi_cmd_t *msg) {
    if (!ipmi_ctx || !msg) {
        printf("<error> send_recv_command: Get empty inputs!\n");
        return -1;
    }

    if (DEBUG_LOG >= 2) {
        printf("     * ipmi command     : 0x%x/0x%x\n", msg->netfn, msg->cmd);
        printf("     * ipmi data length : %d\n", msg->data_len);
        printf("     * ipmi data        : ");

        /* IPMI data max print limit is 10 */
        int max_data_print = 10;

        if (msg->data_len <= max_data_print)
            max_data_print = msg->data_len;

        for (int i=0; i<max_data_print; i++)
            printf("0x%x ", msg->data[i]);
        printf("...\n");
    }

    int oem_flag = 0;

    if ( (msg->netfn >> 2) == OEM_36 || (msg->netfn >> 2) == OEM_38) {
        msg->data_len += 3;
        if (msg->data_len > MAX_IPMB_SIZE)
            return -1;
        oem_flag = 1;
    }

    uint8_t *ipmi_data;
    int init_idx = 0;
    ipmi_data = (uint8_t*)malloc(msg->data_len + 1);// Insert one byte from the head.
    if (!ipmi_data) {
        printf("<error> send_recv_command: ipmi_data malloc failed!\n");
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
    if (!(bytes_rs = calloc (65536*2, sizeof (uint8_t))))
    {
        printf("<error> send_recv_command: bytes_rs calloc failed!\n");
        return -1;
    }

    rs_len = ipmi_cmd_raw(
        ipmi_ctx,
        msg->netfn & 0x03,
        msg->netfn >> 2,
        ipmi_data, //byte #0 = cmd
        msg->data_len + 1, // Add 1 because the cmd is combined with the data buf.
        bytes_rs,
        65536*2
    );

    /* Check for ipmi-raw command response */
    if (bytes_rs[0] != msg->cmd || bytes_rs[1] != CC_SUCCESS)
    {
        printf("<error> send_recv_command: ipmi-raw received bad cc 0x%x\n", bytes_rs[1]);
        return bytes_rs[1];
    }

    /* Check for oem iana */
    if (oem_flag) {
        if (bytes_rs[2]!=IANA_1 || bytes_rs[3]!=IANA_2 || bytes_rs[4]!=IANA_3) {
            printf("<error> send_recv_command: ipmi-raw received invalid IANA\n");
            return -1;
        }
    }

    return CC_SUCCESS;
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
int do_bic_update(uint8_t *buff, uint32_t buff_len) {
    if (!buff) {
        printf("<error> do_bic_update: Get empty inputs!\n");
        return 1;
    }

    ipmi_ctx_t ipmi_ctx = ipmi_ctx_create();
    if (ipmi_ctx == NULL)
    {
        printf("<error> do_bic_update: ipmi_ctx_create error\n");
        return 1;
    }

    ipmi_ctx->type = IPMI_DEVICE_OPENIPMI;
    if (!(ipmi_ctx->io.inband.openipmi_ctx = ipmi_openipmi_ctx_create ()))
    {
        printf("<error> do_bic_update: !(ipmi_ctx->io.inband.openipmi_ctx = ipmi_openipmi_ctx_create ())\n");
        return 1;
    }

    if (ipmi_openipmi_ctx_io_init (ipmi_ctx->io.inband.openipmi_ctx) < 0)
    {
        printf("<error> do_bic_update: ipmi_openipmi_ctx_io_init (ctx->io.inband.openipmi_ctx) < 0\n");
        return 1;
    }

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
        if (section_offset == SECTOR_SZ_64K) {
            section_offset = 0;
            section_idx++;
        }

        /* If current size over 64K */
        if ( (section_offset + MAX_IPMB_DATA_SIZE) / SECTOR_SZ_64K )
            msg_len = (SECTOR_SZ_64K - section_offset);
        else
            msg_len = MAX_IPMB_DATA_SIZE;

        /* If next msg offset over given img length */
        if ( (cur_msg_offset + msg_len) >= buff_len) {
            msg_len = (buff_len - cur_msg_offset);
            last_cmd_flag = 1;
        }

        /* SEND COMMAND HERE */
        fw_update_data_t cmd_data;
        if (last_cmd_flag)
            cmd_data.target = 0x82;
        else
            cmd_data.target = 0x02;

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
                printf("         update status %d%%\n", percent);
        }

        ipmi_cmd_t msg_out;
        msg_out.netfn = FW_UPDATE_NETFN << 2;
        msg_out.cmd = FW_UPDATE_CMD;
        msg_out.data_len = msg_len+7;
        memcpy(msg_out.data, &cmd_data, msg_len+7); /* todo */

        if (DEBUG_LOG >= 1) {
            printf("<debug> section_idx[%d] section_offset[0x%x/0x%x] image_offset[0x%x]\n",
                   section_idx, section_offset, SECTOR_SZ_64K, cur_msg_offset);
            /* custom print for each command */
            printf("        target[0x%x] offset[0x%x] size[%d]\n",
                    msg_out.data[0],
                    msg_out.data[1]|(msg_out.data[2] << 8)|(msg_out.data[3] << 16)|(msg_out.data[4] << 24),
                    msg_out.data[5]|(msg_out.data[6] << 8));
        }

        int resp_cc = send_recv_command(ipmi_ctx, &msg_out);
        if (resp_cc) {
            /* to handle unexpected user interrupt-behavior last time */
            if (resp_cc == CC_INVALID_DATA_FIELD) {
                printf("<warn> Given update offset not mach with previous record!\n");
                printf("       Retry in few seconds...\n");
            }
            return 1;
        }

        cur_msg_offset += msg_len;
        cur_buff += msg_len;
        section_offset += msg_len;

        if (cur_msg_offset == (SECTOR_SZ_64K + 1000))
            break;
    }

    return 0;
}

/*
  - Name: fw_update
  - Description: Firmware update controller
  - Input:
      * flag: Image type flag
      * buff: Buffer to store image bytes
      * buff_len: Buffer length
  - Return:
      * 0, if no error
      * 1, if error
*/
int fw_update(fw_type_t flag, uint8_t *buff, uint32_t buff_len) {
    if (!buff) {
        printf("<error> fw_update: Get empty inputs!\n");
        return 1;
    }

    switch(flag)
    {
    case FW_T_BIC:
        ;
        int retry = 0;
        while (retry <= IPMI_RAW_RETRY)
        {
            if (retry)
                printf("<system> BIC update retry %d/%d ...\n", retry, IPMI_RAW_RETRY);

            int ret = do_bic_update(buff, buff_len)
            if (!ret)
                break;
            retry++;
        }
        if (retry > IPMI_RAW_RETRY)
            return 1;
        break;
    case FW_T_BIOS:
        printf("<warn> BIOS update hasn't support yet!\n");
        return 1;
        break;
    case FW_T_CPLD:
        printf("<warn> CPLD update hasn't support yet!\n");
        return 1;
        break;
    default:
        printf("<error> fw_update: No such flag!\n");
        return 1;
        break;
    }

    return 0;
}

void HELP() {
    printf("Try: ./host_fw_update <fw_type> <img_path> <log_level>\n");
    printf("     <fw_type>   Firmware type [0]BIC [1]BIOS [2]CPLD\n");
    printf("     <img_path>  Image path\n");
    printf("     <log_level> (optional) Log level [-v]L1 [-vv]L2 [-vvv]L3\n\n");
}

void HEADER_PRINT() {
    printf("===============================================================================\n");
    printf("* Name         : %s\n", PROJ_NAME);
    printf("* Description  : %s\n", PROJ_DESCRIPTION);
    printf("* Ver/Date     : %s/%s\n", PROJ_VERSION, PROJ_DATE);
    printf("* Author       : %s\n", PROJ_AUTH);
    printf("* Note         : %s\n", "none");
    printf("===============================================================================\n");
}

int main(int argc, const char** argv)
{
    HEADER_PRINT();

    if (argc!=3 && argc!=4) {
        HELP();
        return 0;
    }

    if (argc == 4) {
        if (strstr(argv[3], "-v"))
            DEBUG_LOG = 1;
        if (strstr(argv[3], "-vv"))
            DEBUG_LOG = 2;
        if (strstr(argv[3], "-vvv"))
            DEBUG_LOG = 3;
    }

    int img_idx = atoi(argv[1]);
    const char *img_path = argv[2];

    if ( (img_idx >= FW_T_MAX_IDX) || (img_idx < 0) ) {
        printf("<error> Invalid <fw_type>!\n");
        HELP();
        return 0;
    }

    if (!DEBUG_LOG)
        printf("<system> Detail ignore...\n");
    else
        printf("<system> Detail leven %d...\n", DEBUG_LOG);

    printf("\n<system> Start [%s] update task with image [%s]\n", IMG_TYPE_LST[img_idx], img_path);

    uint8_t *img_buff = malloc(sizeof(uint8_t) * MAX_IMG_LENGTH);
    if (!img_buff) {
        printf("<error> img_buff malloc failed!\n");
        return 0;
    }

    /* STEP1 - Read image */
    printf("\n<system> STEP1. Read image\n");
    uint32_t img_size = read_binary(img_path, img_buff, MAX_IMG_LENGTH);
    if (!img_size) {
        printf("\n<system> Update failed!\n");
        goto ending;
    }
    printf("<system> PASS!\n");

    /* STEP2 - Upload image */
    printf("\n<system> STEP2. Upload image\n");
    if ( fw_update(img_idx, img_buff, img_size) ) {
        printf("\n<system> Update failed!\n");
        goto ending;
    }
    printf("<system> PASS!\n");

    printf("\n<system> Update complete!\n");

ending:
    if (img_buff)
        free(img_buff);

    return 0;
}
