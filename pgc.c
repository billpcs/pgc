/*
  A program to create L2 frame pcap files (not intersted in IP/TCP etc)
  Supports VLANs!
*/

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#include <winsock2.h>
#elif __linux
#include <arpa/inet.h>
#else
#error "Not supported platform"
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <config.h>

#define DEFAULT_FILE_NAME "paibuild.pcap"
#define DEFAULT_LENGTH 666
#define DEFAULT_DST_MAC "08:00:27:4C:27:11"
#define DEFAULT_SRC_MAC "08:00:27:2A:09:13"
#define DEFAULT_VID 100
#define DEFAULT_ETHERTYPE 0x8100
#define DEFAULT_PRIO 0
#define DEFAULT_DEI 0

#define MAX_FRAME_SIZE 1500
#define MAC_ADDRESS_BYTES 6
#define MAX_VLANS 20

#define FILE_ERROR -1
#define MEMORY_ERROR -2
#define CLI_ERROR -3

#define EXIT_ERROR(s, c)          \
  {                               \
    cleanup();                    \
    fprintf(stderr, "%s\n", (s)); \
    exit(c);                      \
  }

#define CHECK_FWRITE1(ret)                     \
  {                                            \
    if ((ret) != 1)                            \
      EXIT_ERROR("fwrite failed", FILE_ERROR); \
  }

#define CHECK_MALLOC(ret)                        \
  {                                              \
    if ((ret) == NULL)                           \
      EXIT_ERROR("malloc failed", MEMORY_ERROR); \
  }

#define CHECK_FD(fd)                        \
  {                                              \
    if ((fd) == NULL)                           \
      EXIT_ERROR("fd is NULL", FILE_ERROR); \
  }

typedef struct pcap_hdr_s
{
  uint32_t magic_number;  /* magic number */
  uint16_t version_major; /* major version number */
  uint16_t version_minor; /* minor version number */
  int32_t thiszone;       /* GMT to local correction */
  uint32_t sigfigs;       /* accuracy of timestamps */
  uint32_t snaplen;       /* max length of captured packets, in octets */
  uint32_t network;       /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s
{
  uint32_t ts_sec;   /* timestamp seconds */
  uint32_t ts_usec;  /* timestamp microseconds */
  uint32_t incl_len; /* number of octets of packet saved in file */
  uint32_t orig_len; /* actual length of packet */
} pcaprec_hdr_t;

typedef struct vlan_s
{
  uint16_t tpid; /* 0x8100, 0x88a8, 0x9100, 0x9200 */

  uint16_t tci; /* 12 lsb are the vlan value (0-4096)
                   3 msb are the priority value (0-7)
                   the 4th is the Drop Eligible Bit */

} vlan_t;

typedef struct vlan_parser_s
{
  uint8_t ethertype_is_default;
  uint8_t vid_is_default;
  uint8_t dei_is_default;
  uint8_t prio_is_default;
  vlan_t vlan;
} vlan_parser_t;

void cleanup(void) { return; }

void set_tpid_value(vlan_t *vlan, uint16_t value) { vlan->tpid = value; }

void set_vid_value(vlan_t *vlan, uint16_t value)
{
  vlan->tci = (vlan->tci & 0xf000) | (value & 0x0fff);
}

void set_prio_value(vlan_t *vlan, uint16_t value)
{
  vlan->tci = ((value << 13) & 0xe000) | (vlan->tci & 0x1fff) ;
}

void set_dei_value(vlan_t *vlan, uint16_t value)
{
  vlan->tci = (vlan->tci & 0xe000) | ((value << 12) & 0x1000) | (vlan->tci & 0x0fff);
}

// parse the str and save it into mac
void set_mac(uint8_t *mac, const char *str)
{

  char* init = strdup(str);

  int i = 0;
  char *str_byte = strtok(init, ":");
  while (str_byte != NULL)
  {
    mac[i++] = (uint8_t)strtol(str_byte, NULL, 16);
    str_byte = strtok(NULL, ":");
  }

  free(init);
}

void print_mac(uint8_t *mac)
{
  printf("%2x:%2x:%2x:%2x:%2x:%2x\n", mac[0], mac[1], mac[2], mac[3], mac[4],
         mac[5]);
}

uint8_t pcap_init(FILE **f, const char *filename)
{
  *f = fopen(filename, "w");

  if (*f == NULL)
    EXIT_ERROR("Could not create file", FILE_ERROR);

  return 0;
}

uint8_t pcap_write_pcap_header(FILE *f, pcap_hdr_t *hdr)
{
  CHECK_FD(f);
  CHECK_FWRITE1(fwrite((const void *)hdr, sizeof(pcap_hdr_t), 1, f));
}

uint8_t pcap_write_pcap_rec_header(FILE *f, pcaprec_hdr_t *rec)
{
  CHECK_FD(f);
  CHECK_FWRITE1(fwrite((const void *)rec, sizeof(pcaprec_hdr_t), 1, f));
}

uint8_t pcap_write(FILE *f, void *data, uint32_t size)
{
  CHECK_FD(f);
  CHECK_FWRITE1(fwrite((const void *)data, size, 1, f))
}

uint8_t pcap_finalize(FILE *f) { return fclose(f); }

void populate_global_pcap_header(pcap_hdr_t *hdr)
{
  hdr->magic_number = 0xa1b2c3d4;
  hdr->version_major = 2;
  hdr->version_minor = 4;
  hdr->thiszone = 0;
  hdr->sigfigs = 0;
  hdr->snaplen = MAX_FRAME_SIZE;
  hdr->network = 1; // LINKTYPE_ETHERNET
}

void parser_safe_set_ethertype(vlan_parser_t* vlan_parse, uint16_t ethertype, uint8_t def) {
  if (def && vlan_parse->ethertype_is_default) {
    set_tpid_value(&vlan_parse->vlan, DEFAULT_ETHERTYPE);
  }
  else if (vlan_parse->ethertype_is_default) {
    vlan_parse->ethertype_is_default = 0;
    set_tpid_value(&vlan_parse->vlan, ethertype);
  }
}

void parser_safe_set_prio(vlan_parser_t* vlan_parse, uint16_t prio, uint8_t def) {
  if (def && vlan_parse->prio_is_default) {
    set_prio_value(&vlan_parse->vlan, DEFAULT_PRIO);
  }
  else if (vlan_parse->prio_is_default) {
    vlan_parse->prio_is_default = 0;
    set_prio_value(&vlan_parse->vlan, prio);
  }
}

void parser_safe_set_dei(vlan_parser_t* vlan_parse, uint16_t dei, uint8_t def) {
  if (def && vlan_parse->dei_is_default) {
    set_dei_value(&vlan_parse->vlan, DEFAULT_DEI);
  }
  else if (vlan_parse->dei_is_default) {
    vlan_parse->dei_is_default = 0;
    set_dei_value(&vlan_parse->vlan, dei);
  }
}

void parser_safe_set_vid(vlan_parser_t* vlan_parse, uint16_t vid, uint8_t def) {
  if (def && vlan_parse->vid_is_default) {
    set_vid_value(&vlan_parse->vlan, DEFAULT_VID);
  }
  else if (vlan_parse->vid_is_default) {
    vlan_parse->vid_is_default = 0;
    set_vid_value(&vlan_parse->vlan, vid);
  }
}

void parse_vlan_related_option(char type, const char* arg, vlan_parser_t* vlan_parse, uint8_t* pos) {
  uint8_t i = *pos;
  switch (type) {
    case 'v':
      if (vlan_parse[i].vid_is_default) {
        parser_safe_set_vid(&vlan_parse[i], atoi(arg), 0);
        parser_safe_set_ethertype(&vlan_parse[i], DEFAULT_ETHERTYPE, 1);
        parser_safe_set_prio(&vlan_parse[i], DEFAULT_PRIO, 1);
        parser_safe_set_dei(&vlan_parse[i], DEFAULT_DEI, 1);
      } else {
        *pos = i + 1;
        parse_vlan_related_option(type, arg, vlan_parse, pos);
      }
      break;
    case 'e':
      if (vlan_parse[i].ethertype_is_default) {
        parser_safe_set_ethertype(&vlan_parse[i], strtol(arg, NULL, 16), 0);
        parser_safe_set_vid(&vlan_parse[i], DEFAULT_VID, 1);
        parser_safe_set_prio(&vlan_parse[i], DEFAULT_PRIO, 1);
        parser_safe_set_dei(&vlan_parse[i], DEFAULT_DEI, 1);
      } else {
        *pos = i + 1;
        parse_vlan_related_option(type, arg, vlan_parse, pos);
      }
      break;
    case 'p':
      if (vlan_parse[i].prio_is_default) {
        parser_safe_set_prio(&vlan_parse[i], atol(arg), 0);
        parser_safe_set_vid(&vlan_parse[i], DEFAULT_VID, 1);
        parser_safe_set_ethertype(&vlan_parse[i], DEFAULT_ETHERTYPE, 1);
        parser_safe_set_dei(&vlan_parse[i], DEFAULT_DEI, 1);
      } else {
        *pos = i + 1;
        parse_vlan_related_option(type, arg, vlan_parse, pos);
      }
      break;
    case 'i':
      if (vlan_parse[i].dei_is_default) {
        parser_safe_set_dei(&vlan_parse[i], atol(arg), 0);
        parser_safe_set_vid(&vlan_parse[i], DEFAULT_VID, 1);
        parser_safe_set_ethertype(&vlan_parse[i], DEFAULT_ETHERTYPE, 1);
        parser_safe_set_prio(&vlan_parse[i], DEFAULT_PRIO, 1);
      } else {
        *pos = i + 1;
        parse_vlan_related_option(type, arg, vlan_parse, pos);
      }
      break;
    default:
      return;
  }
}

void populate_packet_pcap_header(pcaprec_hdr_t *rec, uint32_t size)
{
  rec->ts_sec = 0;
  rec->ts_usec = 0;
  rec->incl_len = size;
  rec->orig_len = size;
}

void print_help(void)
{
  printf("\nHello.\n");

  printf("\t __  ___  __\n"
         "\t((_)((_( ((_ \n"
         "\t ))   _)) v%d.%d\n\n", pgc_VERSION_MAJOR, pgc_VERSION_MINOR);

  printf("pgc: Generate pcap files from the command line!\n\n\n");

  printf("(Default values in square brackets)\n\n");

  printf("-f: Set the output file name          [%s]\n", DEFAULT_FILE_NAME);
  printf("-s: Set the source MAC                [%s]\n", DEFAULT_SRC_MAC);
  printf("-d: Set the destination MAC           [%s]\n", DEFAULT_DST_MAC);
  printf("-e: Set the ethertype                 [0x%x]\n", DEFAULT_ETHERTYPE);
  printf("-v: Set the VLAN ID                   [%d]\n", DEFAULT_VID);
  printf("-p: Set the VLAN Priority             [%d]\n", DEFAULT_PRIO);
  printf("-i: Set the DEI bit                   [%d]\n", DEFAULT_DEI);
  printf("-l: The length of the frame in bytes  [%d]\n", DEFAULT_LENGTH);
  printf("-h: This message\n");

  printf("\n\nMandatory examples:\n");
  printf("\n");
  printf("Ethertype 0x88a8, vlan 222, priority 7, size 256\n");
  printf("./pgc -e 0x88a8 -v 222 -p 7 -l 256 -f frame_88a8_222.pcap\n");

  printf("\n\n");
  printf("Ethertype 0x%x, vlan %d, priority %d, size 40 with DEI set\n",
         DEFAULT_ETHERTYPE, DEFAULT_VID, DEFAULT_PRIO);
  printf("./pgc -i 1 -l 40 -f frame_8100_100_dei.pcap\n");

  printf("\n\n");
  printf("Report bugs to: me\n");
}

int main(int argc, char *argv[])
{

  FILE *pcap_file;
  uint16_t num_vlans = 0;
  uint8_t src_mac[MAX_FRAME_SIZE] = {0};
  uint8_t dst_mac[MAX_FRAME_SIZE] = {0};
  uint8_t data[MAX_FRAME_SIZE] = {0};
  uint8_t vlan_counter = 0;
  vlan_parser_t* vlans = malloc(MAX_VLANS * sizeof(vlan_parser_t));
  CHECK_MALLOC(vlans);

  for (int n = 0; n < MAX_VLANS; n++) {
    vlans[n].ethertype_is_default = 1;
    vlans[n].vid_is_default = 1;
    vlans[n].prio_is_default = 1;
    vlans[n].dei_is_default = 1;
  }

  // CLI variables
  uint8_t cli_pcap_name = 0, cli_length = 0, cli_src_mac = 0, cli_dst_mac = 0;
  int32_t c;

  uint32_t frame_size;
  char filename[50];

  while ((c = getopt(argc, argv, "hf:s:d:v:i:e:p:l:")) != -1)
  {
    switch (c)
    {
    case 'h':
      print_help();
      exit(0);
    case 'f':
      cli_pcap_name = 1;
      strcpy(filename, optarg);
      break;
    case 's':
      cli_src_mac = 1;
      set_mac(src_mac, optarg);
      break;
    case 'd':
      cli_dst_mac = 1;
      set_mac(dst_mac, optarg);
      break;
    case 'v': // vlan
    case 'e': // ethertype
    case 'i': // dei
    case 'p': // prio
      parse_vlan_related_option(c, optarg, vlans, &vlan_counter);
      break;
    case 'l':
      cli_length = 1;
      frame_size = atol(optarg);
      break;
    default:
      printf("%c %d\n", c, c);
      break;
    }
  }

  // these have to be set in every frame
  if (!cli_pcap_name)
    strcpy(filename, DEFAULT_FILE_NAME);

  if (!cli_length)
    frame_size = DEFAULT_LENGTH;

  if (!cli_src_mac)
    set_mac(src_mac, DEFAULT_SRC_MAC);

  if (!cli_dst_mac)
    set_mac(dst_mac, DEFAULT_DST_MAC);

  pcap_hdr_t hdr;
  pcaprec_hdr_t rec;

  populate_global_pcap_header(&hdr);
  populate_packet_pcap_header(&rec, frame_size);

  pcap_init(&pcap_file, filename);
  pcap_write_pcap_header(pcap_file, &hdr);
  pcap_write_pcap_rec_header(pcap_file, &rec);

  pcap_write(pcap_file, &dst_mac, MAC_ADDRESS_BYTES);
  pcap_write(pcap_file, &src_mac, MAC_ADDRESS_BYTES);

  for (int i = 0; i <= vlan_counter; i++) {
    uint16_t tci = ntohs(vlans[i].vlan.tci);
    uint16_t tpid = ntohs(vlans[i].vlan.tpid);
    pcap_write(pcap_file, &tpid, 2);
    pcap_write(pcap_file, &tci, 2);
  }

  // write IP ethertype
  uint16_t ip = htons(0x0800);
  pcap_write(pcap_file, &ip, 2);

  // write the rest of the zeros
  pcap_write(pcap_file, data, frame_size - 2 * MAC_ADDRESS_BYTES - (vlan_counter + 1)*sizeof(struct vlan_s) - sizeof(ip));
  pcap_finalize(pcap_file);

  // free everything
  free(vlans);

  return 0;
}
