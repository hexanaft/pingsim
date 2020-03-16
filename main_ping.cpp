#include <cstdio>
#include <getopt.h>
#include "device_ping.h"

/*!
 * \brief Display interface to use
 */
void display_usage(void)
{
    printf("Usage: pinghr destination\n");
    printf("\t-h --help         - print help\n");

    printf("\t-s                - packetsize\n");
    printf("\t-f                - fragmentation off\n");
}

int main(int argc, char *argv[])
{
//    setbuf(stdout, NULL); // TODO: remove, need only for debug on cross gdb
    printf("Ping device:\n");

    if (argc < 2) {
        display_usage();
        return -1;
    }
    const char *short_options = {"hs:f"}; // x: - mean x have parametr

    std::string addr;
    uint32_t packetsize = 0;
    bool fragmentation = false;

    int opt;
    do {
        opt = getopt(argc, argv, short_options);
        switch (opt) {
            case 'h': {
                display_usage();
            } break;

            case 's': {
                if (optarg) {
                    sscanf(optarg, "%u", &packetsize);
                    printf("\t packetsize %u\n", packetsize);
                }
            } break;

            case 'f': {
                printf("\t fragmentation off by default (TODO)\n");
            } break;

            default: {
                printf("\t ping '%s'\n", argv[optind]);
                addr.assign(argv[optind]);
            } break;
        }
    } while (opt != -1);

    if (addr.empty()) return -2;

    dev_ping p;
    dev_ping::result_t ping_result;
    if (packetsize) p.setSize(packetsize);
    bool ok = p.check(addr, &ping_result);
    printf("Ping: %s\n", ok ? "ok" : "fail");
    printf("%s", ping_result.status.c_str());

    return 0;
}
