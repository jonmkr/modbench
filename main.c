#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <modbus.h>
#include <errno.h>
#include <sys/time.h>

int main(int argc, char *argv[]) {
    int iters;
    char host[20];
    int mode;
    
    int opt;
    while ((opt = getopt(argc, argv, "sh:i:")) != -1) {
        switch (opt) {
            case 's':
                mode = 1; // Server mode
                break;
            case 'h':
                strcpy(host, optarg);
                break;
            case 'i':
                iters = atoi(optarg);
                break;
        }
    }

    if (mode == 1) { // Server mode
        int s = -1;
        modbus_t *ctx;
        modbus_mapping_t *mb_mapping;

        ctx = modbus_new_tcp("127.0.0.1", 1502);
        mb_mapping = modbus_mapping_new(2000, 500, 500, 500);

        printf("Listening...\n");
        s = modbus_tcp_listen(ctx, 1);

        for (;;) {
            modbus_tcp_accept(ctx, &s);
            printf("Connection successful\n");
            
            uint8_t query[MODBUS_TCP_MAX_ADU_LENGTH];
            
            for (;;) {
                int rc = modbus_receive(ctx, query);
                if (rc > 0) {
                    modbus_reply(ctx, query, rc, mb_mapping);
                } else {
                    break;
                }
            }
        }

        close(s);
        modbus_close(ctx);
        modbus_free(ctx);
        return 0;
    }

    if (mode == 0) { // Client mode
        modbus_t *ctx;
        uint16_t tab_reg[32];

        ctx = modbus_new_tcp(host, 1502);
        int s = modbus_connect(ctx);

        if (s == -1) {
            printf("%s\n", modbus_strerror(errno));
            modbus_free(ctx);
            return 0;
        }

        //printf("Connection successful\n");

        int n_rq_bits = MODBUS_MAX_WRITE_BITS;
        uint8_t *rq_bits;
        rq_bits = (uint8_t *) malloc(n_rq_bits * sizeof(uint8_t));
        memset(rq_bits, 0, n_rq_bits*sizeof(uint8_t));

        struct timeval start;
        struct timeval end;

        typedef struct sample{
            struct timeval ts;
            struct timeval latency;
        } sample;
        
        if (iters == 0) {
             iters = 1000000;
        }

        struct sample *results = malloc(sizeof(sample)* iters);

        for (int i = 0; i < iters; i++){
            gettimeofday(&start, NULL);
            
            int rc;
            rc = modbus_write_bits(ctx, 0, n_rq_bits, rq_bits);
            if (rc == 0) {
                printf("Request failed: %s", modbus_strerror(errno));
            }

            gettimeofday(&end, NULL);
            results[i].ts = end;
            timersub(&end, &start, &results[i].latency);
        }

        for (int i = 0; i < iters; i++) {
            struct timeval ts = results[i].ts;
            struct timeval latency = results[i].latency;
            printf("%ld %ld %ld \n", ts.tv_sec, ts.tv_usec, (long int)(latency.tv_sec * 1.0e6) + latency.tv_usec);
        }

        free(results);
        modbus_close(ctx);
        modbus_free(ctx);
    }
}