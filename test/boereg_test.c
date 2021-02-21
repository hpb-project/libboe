#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "boe.h"

int ch_to_int(char ch)
{
    if(ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return 0;
}

void string_to_int(char *str, unsigned int *data)
{
    int i = 0, j = 0;
    int len = strlen(str);

    unsigned int num = 0;
    unsigned int sum = 0;

    printf(" str addr len : %d\n",len);


    if(('0' == *str)&&(('x' == *(str+1))||('X' == *(str + 1))))
    {
        len = len - 2;
        str = str + 2; 
        for(j = 0;j < len; j ++)
        {
            sum *= 16;
            num = ch_to_int(str[j]);
            sum += num;

        }

        printf("16to10 sum  0x%x\n",sum);
    }
    else
    {
        sum = atoi(str);

        printf("10 sum: %d\n",sum);
    }

    *data = sum;

}

int main(int argc, char *argv[])
{
    unsigned int read_data = 0;
    int i = 0;
    unsigned int addr = 0;
    unsigned int write_data = 0;
    char *str = NULL;

    if((3 != argc)&&(4 != argc))
    {
        printf("cmd type is error !\n");
        return 1;
    }

    BoeErr *ret = boe_init();
    if(ret != BOE_OK)
    {
        printf("init failed.\r\n");
        return 1;
    }


    if(3 == argc)
    {
        if((!strcmp("r",argv[1]))||(!strcmp("R",argv[1])))
        {
            printf("read reg addr: %s\n",argv[2]);

            str = argv[2];
            string_to_int(str, &addr);
            printf("reg=0x%x\r\n", addr);

            ret = boe_reg_read(addr,&read_data);
            if(ret != BOE_OK)
            {
                printf("boe_reg_read failed.\r\n");
                return 1;
            }
            else
            {			
                printf("read reg ok data: %d\n", read_data);
            }

        }
        else
        {
            printf("read cmd type error !\n");
        }
    }
    else if(4 == argc)
    {
        if((!strcmp("w",argv[1]))||(!strcmp("W",argv[1])))
        {
            printf("wirte addr %s  data %s \n", argv[2],argv[3]);
            str = argv[2];
            string_to_int(str, &addr);
            printf("reg=0x%x\r\n", addr);
            str = argv[3];
            string_to_int(str, &write_data);
            printf("val=0x%x\r\n", write_data);


            ret = boe_reg_write(addr,write_data);
            if(ret != BOE_OK)
            {
                printf("boe_reg_write failed.\r\n");
                return 1;
            }
            else
            {
                printf("boe_reg_write ok.\r\n");
            }
        }
        else
        {
            printf("write cmd error \r\n");
            return 1;
        }
    }
    boe_release();

    return 0;
}
