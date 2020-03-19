/*
  A program to create L2 frame pcap files (not intersted in IP/TCP etc)
  Supports VLANs!
*/

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

void cleanup(void) { return; }

void set_tpid_value(vlan_t *vlan, uint16_t value) { vlan->tpid = value; }

void set_vid_value(vlan_t *vlan, uint16_t value)
{
  vlan->tci |= (value & 0x0fff);
}

void set_prio_value(vlan_t *vlan, uint16_t value)
{
  vlan->tci |= (value << 13);
}

void set_dei_value(vlan_t *vlan, uint16_t value)
{
  vlan->tci |= (value << 12) & 0x1000;
}

void set_vlan(vlan_t *vlan, uint16_t tpid, uint16_t vid, uint16_t prio,
              uint16_t dei)
{
  set_tpid_value(vlan, tpid);
  set_vid_value(vlan, vid);
  set_prio_value(vlan, prio);
  set_dei_value(vlan, dei);
  vlan->tci = htons(vlan->tci);
  vlan->tpid = htons(vlan->tpid);
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
  CHECK_FWRITE1(fwrite((const void *)hdr, sizeof(pcap_hdr_t), 1, f));
}

uint8_t pcap_write_pcap_rec_header(FILE *f, pcaprec_hdr_t *rec)
{
  CHECK_FWRITE1(fwrite((const void *)rec, sizeof(pcaprec_hdr_t), 1, f));
}

uint8_t pcap_write(FILE *f, void *data, uint32_t size)
{
  if (f == NULL)
    EXIT_ERROR("Attempted to write on NULL descriptor", FILE_ERROR);

  // write the packet data
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
         "\t ))   _))\n\n");

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
  vlan_t *vlans[MAX_VLANS] = {0};

  uint8_t insert_vlan;

  // CLI variables
  uint8_t cli_pcap_name = 0, cli_length = 0, cli_src_mac = 0, cli_dst_mac = 0;
  uint8_t cli_vid = 0, cli_dei = 0, cli_ethertype = 0, cli_prio = 0;
  int32_t c;

  uint32_t frame_size;
  uint16_t ethertype, vid, prio, dei;
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
    case 'v':
      cli_vid = 1;
      vid = atol(optarg);
      break;
    case 'i':
      cli_dei = 1;
      dei = atol(optarg);
      break;
    case 'e':
      cli_ethertype = 1;
      ethertype = strtol(optarg, NULL, 16);
      break;
    case 'p':
      cli_prio = 1;
      prio = atol(optarg);
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

  // these are optional and take default values only if one of them is set
  if (!cli_ethertype && !cli_vid && !cli_dei && !cli_prio)
  {
    // do not place vlan in the frame
    insert_vlan = 0;
  }
  else
  {
    // if even one is present, set the
    // non-present to their default values
    if (!cli_ethertype)
      ethertype = DEFAULT_ETHERTYPE;

    if (!cli_vid)
      vid = DEFAULT_VID;
    if (!cli_dei)
      dei = DEFAULT_DEI;
    if (!cli_prio)
      prio = DEFAULT_PRIO;

    insert_vlan = 1;
  }

  pcap_hdr_t hdr;
  pcaprec_hdr_t rec;

  if (insert_vlan)
  {
    vlans[0] = malloc(sizeof(vlan_t));
    CHECK_MALLOC(vlans[0]);
    memset(vlans[0], 0, sizeof(vlan_t));
    set_vlan(vlans[0], ethertype, vid, prio, dei);
  }

  populate_global_pcap_header(&hdr);
  populate_packet_pcap_header(&rec, frame_size);

  pcap_init(&pcap_file, filename);
  pcap_write_pcap_header(pcap_file, &hdr);
  pcap_write_pcap_rec_header(pcap_file, &rec);

  fwrite(&dst_mac, MAC_ADDRESS_BYTES, 1, pcap_file);
  fwrite(&src_mac, MAC_ADDRESS_BYTES, 1, pcap_file);

  int i = 0;
  while (vlans[i] != NULL)
    fwrite(vlans[i++], sizeof(struct vlan_s), 1, pcap_file);

  // write IP ethertype
  uint16_t ip = htons(0x0800);
  fwrite(&ip, 2, 1, pcap_file);

  // write the rest of the zeros
  pcap_write(pcap_file, data, frame_size - 2 * MAC_ADDRESS_BYTES - sizeof(struct vlan_s) - sizeof(ip));
  pcap_finalize(pcap_file);

  // free everything
  uint16_t n = 0;
  while (vlans[n] != NULL)
    free(vlans[n++]);

  return 0;
}
