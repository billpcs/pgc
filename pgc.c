/*
  A program to create L2 frame pcap files (not interested in IP/TCP etc)
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
#include <time.h>

#define VERSION_MAJOR     0
#define VERSION_MINOR     5

#define DEFAULT_FILE_NAME "paibuild.pcap"
#define DEFAULT_LENGTH 666
#define DEFAULT_DST_MAC "08:00:27:4C:27:11"
#define DEFAULT_SRC_MAC "08:00:27:2A:09:13"
#define DEFAULT_VID 100
#define DEFAULT_TPID 0x8100
#define DEFAULT_ETHERTYPE 0x0800
#define DEFAULT_PRIO 0
#define DEFAULT_DEI 0

#define VLAN_VALUE_MIN 0
#define VLAN_VALUE_MAX 4095

#define MAX_FRAME_SIZE 1500
#define MAC_ADDRESS_BYTES 6
#define MAX_VLANS 20
#define MAX_RAW_BYTES (MAX_FRAME_SIZE - 2*MAC_ADDRESS_BYTES)

#define MAX_FILENAME_LEN 50

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
  uint8_t tpid_is_default;
  uint8_t vid_is_default;
  uint8_t dei_is_default;
  uint8_t prio_is_default;
  vlan_t vlan;
} vlan_parser_t;

void cleanup(void) { return; }

void set_tpid_value(vlan_t *vlan, uint16_t value) { vlan->tpid = value; }

long parse_number(const char *str, int base, long min, long max, const char *name)
{
  char *end;
  long value = strtol(str, &end, base);

  if (*str == '\0' || *end != '\0' || value < min || value > max) {
    fprintf(stderr, "Invalid %s value: %s\n", name, str);
    exit(CLI_ERROR);
  }

  return value;
}

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

void set_mac(uint8_t *mac, const char *str)
{
  char *init = strdup(str);
  char *end;
  int i = 0;

  CHECK_MALLOC(init);

  char *str_byte = strtok(init, ":");

  while (str_byte != NULL) {
    if (i >= MAC_ADDRESS_BYTES)
        EXIT_ERROR("Invalid MAC address", CLI_ERROR);

    long value = strtol(str_byte, &end, 16);

    if (*str_byte == '\0' || *end != '\0' || value < 0 || value > 0xff)
        EXIT_ERROR("Invalid MAC address", CLI_ERROR);

    mac[i++] = (uint8_t)value;
    str_byte = strtok(NULL, ":");
  }

  if (i != MAC_ADDRESS_BYTES)
      EXIT_ERROR("Invalid MAC address", CLI_ERROR);

  free(init);
}

void print_mac(uint8_t *mac)
{
  printf("%2x:%2x:%2x:%2x:%2x:%2x\n", mac[0], mac[1], mac[2], mac[3], mac[4],
         mac[5]);
}

void pcap_init(FILE **f, const char *filename)
{
  *f = fopen(filename, "wb");

  if (*f == NULL)
    EXIT_ERROR("Could not create file", FILE_ERROR);
}

void pcap_write_pcap_header(FILE *f, pcap_hdr_t *hdr)
{
  CHECK_FD(f);
  CHECK_FWRITE1(fwrite((const void *)hdr, sizeof(pcap_hdr_t), 1, f));
}

void pcap_write_pcap_rec_header(FILE *f, pcaprec_hdr_t *rec)
{
  CHECK_FD(f);
  CHECK_FWRITE1(fwrite((const void *)rec, sizeof(pcaprec_hdr_t), 1, f));
}

void pcap_write(FILE *f, void *data, uint32_t size)
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

void parser_safe_set_tpid(vlan_parser_t* vlan_parse, uint16_t tpid, uint8_t def) {
  if (def && vlan_parse->tpid_is_default) {
    set_tpid_value(&vlan_parse->vlan, DEFAULT_TPID);
  }
  else if (vlan_parse->tpid_is_default) {
    vlan_parse->tpid_is_default = 0;
    set_tpid_value(&vlan_parse->vlan, tpid);
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

  if (i >= MAX_VLANS)
    EXIT_ERROR("Too many VLAN tags", CLI_ERROR);

  switch (type) {
    case 'v':
      if (vlan_parse[i].vid_is_default) {
        parser_safe_set_vid(&vlan_parse[i], parse_number(arg, 10, VLAN_VALUE_MIN, VLAN_VALUE_MAX, "VLAN ID"), 0);
        parser_safe_set_tpid(&vlan_parse[i], DEFAULT_TPID, 1);
        parser_safe_set_prio(&vlan_parse[i], DEFAULT_PRIO, 1);
        parser_safe_set_dei(&vlan_parse[i], DEFAULT_DEI, 1);
      } else {
        *pos = i + 1;
        parse_vlan_related_option(type, arg, vlan_parse, pos);
      }
      break;
    case 't':
      if (vlan_parse[i].tpid_is_default) {
        parser_safe_set_tpid(&vlan_parse[i], parse_number(arg, 0, 0, 0xffff, "TPID"), 0);
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
        parser_safe_set_prio(&vlan_parse[i], parse_number(arg, 10, 0, 7, "priority"), 0);
        parser_safe_set_vid(&vlan_parse[i], DEFAULT_VID, 1);
        parser_safe_set_tpid(&vlan_parse[i], DEFAULT_TPID, 1);
        parser_safe_set_dei(&vlan_parse[i], DEFAULT_DEI, 1);
      } else {
        *pos = i + 1;
        parse_vlan_related_option(type, arg, vlan_parse, pos);
      }
      break;
    case 'i':
      if (vlan_parse[i].dei_is_default) {
        parser_safe_set_dei(&vlan_parse[i], parse_number(arg, 10, 0, 1, "DEI"), 0);
        parser_safe_set_vid(&vlan_parse[i], DEFAULT_VID, 1);
        parser_safe_set_tpid(&vlan_parse[i], DEFAULT_TPID, 1);
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

void pcap_write_vlans(FILE* pcap_file, vlan_parser_t* vlans, int num) {
  for (int i = 0; i < num; i++) {
    uint16_t tci = ntohs(vlans[i].vlan.tci);
    uint16_t tpid = ntohs(vlans[i].vlan.tpid);
    pcap_write(pcap_file, &tpid, 2);
    pcap_write(pcap_file, &tci, 2);
  }
}

int string_look_ahead_by(uint16_t num, char* str) {
  char* ptr = str;
  int i;
  for (i = 0; i < num; i++) {
    if (*ptr == '\0') return i;
    ptr++;
  }
  return num;
}


void filter_string(char* in, char** output, char needle) {
  int i = 0, j = 0;
  char* out = *output = strdup(in);
  while(in[i]) {
    if (in[i++] == needle) continue;
    out[j++] = in[i-1];
  }
  out[j] = '\0';
}

void parse_raw(uint8_t* buf, uint32_t buf_size, char* sstring, uint32_t* size) {
  int i, s = 0;
  char substr[3];
  uint32_t size_sum = 0;
  char* string = NULL;
  filter_string(sstring, &string, '/');
  for (i = 0 ;; i++, s+=2) {
    int num_next = string_look_ahead_by(2, &string[s]);
    if (num_next == 0) break;
    memcpy(substr, &string[s], num_next);
    substr[num_next] = '\0';

    if ((uint32_t)i >= buf_size)
        EXIT_ERROR("Raw data too large", CLI_ERROR);

    buf[i] = strtol(substr, NULL, 16);
    size_sum += 1;
    if (num_next != 2) break;
  }
  *size = size_sum;
  free(string);
}

void populate_packet_pcap_header(pcaprec_hdr_t *rec, uint32_t size)
{
  rec->ts_sec = time(NULL);
  rec->ts_usec = 0;
  rec->incl_len = size;
  rec->orig_len = size;
}

void print_help(void)
{
  printf("\nHello.\n");

  printf("\t __  ___  __\n"
         "\t((_)((_( ((_ \n"
         "\t ))   _)) v%d.%d\n\n", VERSION_MAJOR, VERSION_MINOR);

  printf("pgc: Generate pcap files from the command line!\n\n\n");

  printf("(Default values in square brackets)\n\n");

  printf("-f: Set the output file name          [%s]\n", DEFAULT_FILE_NAME);
  printf("-s: Set the source MAC                [%s]\n", DEFAULT_SRC_MAC);
  printf("-d: Set the destination MAC           [%s]\n", DEFAULT_DST_MAC);
  printf("-t: Set the VLAN TPID                 [0x%x]\n", DEFAULT_TPID);
  printf("-e: Set the Ethernet EtherType        [0x%x]\n", DEFAULT_ETHERTYPE);
  printf("-v: Set the VLAN ID                   [%d]\n", DEFAULT_VID);
  printf("-p: Set the VLAN Priority             [%d]\n", DEFAULT_PRIO);
  printf("-i: Set the DEI bit                   [%d]\n", DEFAULT_DEI);
  printf("-l: The length of the frame in bytes  [%d]\n", DEFAULT_LENGTH);
  printf("-r: Set raw data after ethernet header\n");
  printf("-h: This message\n");

  printf("\n\nMandatory examples:\n");
  printf("\n");
  printf("TPID 0x88a8, vlan 222, priority 7, EtherType 0x0800, size 256\n");
  printf("./pgc -t 0x88a8 -v 222 -p 7 -e 0x0800 -l 256 -f frame_88a8_222.pcap\n");

  printf("\n\n");
  printf("TPID 0x%x, vlan %d, priority %d, EtherType 0x%x, size 40 with DEI set\n",
         DEFAULT_TPID, DEFAULT_VID, DEFAULT_PRIO, DEFAULT_ETHERTYPE);
  printf("./pgc -i 1 -l 40 -f frame_8100_100_dei.pcap\n");

  printf("\n\n");
  printf("Report bugs to: me\n");
}

int main(int argc, char *argv[])
{

  FILE *pcap_file;
  uint16_t num_vlans = 0;
  uint8_t src_mac[MAC_ADDRESS_BYTES] = {0};
  uint8_t dst_mac[MAC_ADDRESS_BYTES] = {0};
  uint8_t data[MAX_FRAME_SIZE] = {0};
  uint8_t vlan_counter = 0;
  vlan_parser_t vlans[MAX_VLANS];
  uint8_t raw_data[MAX_RAW_BYTES];
  uint16_t rest_size;

  for (int n = 0; n < MAX_VLANS; n++) {
    vlans[n].tpid_is_default = 1;
    vlans[n].vid_is_default = 1;
    vlans[n].prio_is_default = 1;
    vlans[n].dei_is_default = 1;
  }

  // CLI variables
  uint8_t cli_pcap_name = 0, cli_length = 0, cli_src_mac = 0, cli_dst_mac = 0;
  uint8_t cli_vlan = 0, cli_raw_data = 0;
  uint32_t cli_raw_size;
  int32_t c;

  uint32_t frame_size;
  uint16_t ethertype = DEFAULT_ETHERTYPE;
  char filename[MAX_FILENAME_LEN+1];

  while ((c = getopt(argc, argv, "hf:s:d:v:i:e:t:p:l:r:")) != -1)
  {
    switch (c)
    {
    case 'h':
      print_help();
      exit(0);
    case 'f':
      cli_pcap_name = 1;
      snprintf(filename, sizeof(filename), "%s", optarg);
      break;
    case 's':
      cli_src_mac = 1;
      set_mac(src_mac, optarg);
      break;
    case 'd':
      cli_dst_mac = 1;
      set_mac(dst_mac, optarg);
      break;
    case 'e': // ethernet ethertype
      ethertype = parse_number(optarg, 0, 0, 0xffff, "ethertype");
      break;
    case 'v': // vlan
    case 't': // tpid
    case 'i': // dei
    case 'p': // prio
      cli_vlan = 1;
      parse_vlan_related_option(c, optarg, vlans, &vlan_counter);
      break;
    case 'l':
      cli_length = 1;
      frame_size = parse_number(optarg, 10, 1, MAX_FRAME_SIZE, "frame length");
      break;
    case 'r':
      cli_raw_data = 1;
      parse_raw(raw_data, MAX_RAW_BYTES, optarg, &cli_raw_size);
      break;
    default:
      print_help();
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

  if (cli_vlan) {
    vlan_counter++;
    pcap_write_vlans(pcap_file, vlans, vlan_counter);
  }

  uint16_t ether_type;
  if (!cli_raw_data) {
    ether_type = htons(ethertype);
    pcap_write(pcap_file, &ether_type, sizeof(ether_type));
    rest_size = sizeof(ether_type);
  }
  else {
    pcap_write(pcap_file, (uint8_t*)&raw_data, cli_raw_size);
    rest_size = cli_raw_size;
  }

  uint32_t bytes_written =
      2 * MAC_ADDRESS_BYTES +
      vlan_counter * sizeof(struct vlan_s) +
      rest_size;

  if (bytes_written > frame_size) {
    fprintf(stderr,
            "Frame too small: requested %u bytes, but headers/data require %u bytes\n",
            frame_size, bytes_written);
    pcap_finalize(pcap_file);
    return CLI_ERROR;
  }

  uint32_t zero_s = frame_size - bytes_written;

  // write the rest of the zeros
  if (zero_s > 0)
    pcap_write(pcap_file, data, zero_s);

  pcap_finalize(pcap_file);

  return 0;
}
