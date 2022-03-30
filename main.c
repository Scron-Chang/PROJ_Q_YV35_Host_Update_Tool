#include <stdio.h>
#include <stdlib.h>

#ifdef __UINT8_TYPE__
typedef __UINT8_TYPE__ uint8_t;
#endif

#ifdef __UINT32_TYPE__
typedef __UINT32_TYPE__ uint32_t;
#endif

#define PROJ_NAME "FW UPDATE TOOL"
#define PROJ_DESCRIPTION "Firmware update tool from host, including [BIC] [BIOS] [CPLD]."
#define PROJ_VERSION "v1.0"
#define PROJ_DATE "2022.03.30"
#define PROJ_AUTH "Quanta"

#define MAX_IMG_LENGTH 0x80000
#define MAX_IPMI_DATA_SIZE 244
#define SECTOR_SZ_64K 0x10000

#define DEBUG_LOG 0

typedef enum fw_type {
    FW_T_BIC,
    FW_T_BIOS,
    FW_T_CPLD,
    FW_T_MAX_IDX
} fw_type_t;

char *IMG_TYPE_LST[3] = {"BIC", "BIOS", "CPLD"};

typedef struct ipmi_cmd {
    uint8_t netfn; /* note whether include LUN */
    uint8_t cmd;
    uint8_t data[MAX_IPMI_DATA_SIZE];
}ipmi_cmd_t;

uint32_t read_binary(char *bin_path, uint8_t *buff, uint32_t buff_len) {
    if (!buff)
        return 0;

    FILE *ptr;
    size_t bin_size; /*filesize*/

    ptr = fopen(bin_path,"rb");  // r for read, b for binary
    if (!ptr) {
        printf("<error> Invalid bin file path [%s]\n", bin_path);
        return 0;
    }

    fseek(ptr, 0, SEEK_END);
    bin_size = ftell(ptr);         /*calc the size needed*/
    fseek(ptr, 0, SEEK_SET);

    if (bin_size > buff_len) {
        printf("<error> Given buffer length (0x%x) smaller than Image length (0x%x)\n",
               buff_len, bin_size);
        return 0;
    }

    fread(buff, buff_len, 1, ptr); // read 10 bytes to our buffer

    if (DEBUG_LOG) {
        for (int i=0; i<bin_size; i++)
            printf("[0x%x] ", buff[i]);
        printf("\n");
        printf("<system> Image size: 0x%x\n", bin_size);
    }

    return bin_size;
}

int send_recv_command() {
    /* TODO: Send command here */

    /* TODO: Wait Receive command here */

    return 0;
}

int do_bic_update(uint8_t *buff, uint32_t buff_len) {
    /* TODO: Write update code here */

    if ( send_recv_command() )
        return 1;

    if ( send_recv_command() )
        return 1;

    return 0;
}

int fw_update(fw_type_t flag, uint8_t *buff, uint32_t buff_len) {
    if (!buff) {
        printf("<error> Get empty buffer!\n");
        return 1;
    }

    switch(flag)
    {
    case FW_T_BIC:
        if ( do_bic_update(buff, buff_len) )
            return 1;
        break;
    case FW_T_BIOS:
        break;
    case FW_T_CPLD:
        break;
    default:
        printf("<error> fw_update: No such flag!\n");
        break;
    }

    return 0;
}

void HELP() {
    printf("Try: ./host_fw_update <fw_type> <img_path>\n");
    printf("     <fw_type>  Firmware type [0]BIC [1]BIOS [2]CPLD\n");
    printf("     <img_path> Image path\n\n");
}

void HEADER_PRINT() {
    printf("================================================================\n");
    printf("* Name         : %s\n", PROJ_NAME);
    printf("* Description  : %s\n", PROJ_DESCRIPTION);
    printf("* Ver/Date     : %s/%s\n", PROJ_VERSION, PROJ_DATE);
    printf("* Author       : %s\n", PROJ_AUTH);
    printf("================================================================\n");
}

int main(int argc, const char** argv)
{
    HEADER_PRINT();

    if (argc!=3) {
        HELP();
        return 0;
    }

    int img_idx = atoi(argv[1]);
    char *img_path = argv[2];

    if ( (img_idx >= FW_T_MAX_IDX) || (img_idx < 0) ) {
        printf("<error> Invalid <fw_type>!\n");
        HELP();
        return 0;
    }

    printf("<system> Start [%s] update task with image [%s]\n", IMG_TYPE_LST[img_idx], img_path);

    uint8_t *img_buff = malloc(sizeof(uint8_t) * MAX_IMG_LENGTH);
    if (!img_buff) {
        printf("<error> img_buff malloc failed!\n");
        return 0;
    }

    /* STEP1 */
    printf("<system> STEP1. Read image\n");
    uint32_t img_size = read_binary(img_path, img_buff, MAX_IMG_LENGTH);
    if (!img_size) {
        printf("    --> failed!\n");
        return 0;
    }
    printf("    --> success!\n");

    /* STEP2 */
    printf("<system> STEP2. Upload image\n");
    if ( fw_update(img_idx, img_buff, img_size) ) {
        printf("    --> failed!\n");
        return 0;
    }
    printf("    --> success!\n");

    printf("\n\n<system> Update complete!\n");

    return 0;
}
