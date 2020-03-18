#include <cstdio>
#include "device_ping.h"

#ifndef _MSC_VER
	#include <getopt.h>
#else
int     opterr = 1,             /* if error message should be printed */
  optind = 1,             /* index into parent argv vector */
  optopt,                 /* character checked for validity */
  optreset;               /* reset getopt */
char    *optarg;                /* argument associated with option */

#define BADCH   (int)'?'
#define BADARG  (int)':'
#define EMSG    ""

/*
* getopt --
*      Parse argc/argv argument vector.
*/
int
  getopt(int nargc, char * const nargv[], const char *ostr)
{
  static char *place = EMSG;              /* option letter processing */
  const char *oli;                        /* option letter list index */

  if (optreset || !*place) {              /* update scanning pointer */
    optreset = 0;
    if (optind >= nargc || *(place = nargv[optind]) != '-') {
      place = EMSG;
      return (-1);
    }
    if (place[1] && *++place == '-') {      /* found "--" */
      ++optind;
      place = EMSG;
      return (-1);
    }
  }                                       /* option letter okay? */
  if ((optopt = (int)*place++) == (int)':' ||
    !(oli = strchr(ostr, optopt))) {
      /*
      * if the user didn't specify '-' as an option,
      * assume it means -1.
      */
      if (optopt == (int)'-')
        return (-1);
      if (!*place)
        ++optind;
      if (opterr && *ostr != ':')
        (void)printf("illegal option -- %c\n", optopt);
      return (BADCH);
  }
  if (*++oli != ':') {                    /* don't need argument */
    optarg = NULL;
    if (!*place)
      ++optind;
  }
  else {                                  /* need an argument */
    if (*place)                     /* no white space */
      optarg = place;
    else if (nargc <= ++optind) {   /* no arg */
      place = EMSG;
      if (*ostr == ':')
        return (BADARG);
      if (opterr)
        (void)printf("option requires an argument -- %c\n", optopt);
      return (BADCH);
    }
    else                            /* white space */
      optarg = nargv[optind];
    place = EMSG;
    ++optind;
  }
  return (optopt);                        /* dump back option letter */
}
#endif

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
                return 0;
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
