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
#define DEFAULT_LENGTH "666"
#define DEFAULT_DST_MAC "08:00:27:4C:27:11"
#define DEFAULT_SRC_MAC "08:00:27:2A:09:13"
#define DEFAULT_VID "100"
#define DEFAULT_ETHERTYPE "0x8100"
#define DEFAULT_PRIO "0"
#define DEFAULT_DEI "0"

#define MAX_FRAME_SIZE 1500
#define MAC_ADDRESS_BYTES 6
#define MAX_VLANS 20

#define FILE_ERROR -1
#define MEMORY_ERROR -2
#define CLI_ERROR -3

#define EXIT_ERROR(s, c)                                                       \
  {                                                                            \
    cleanup();                                                                 \
    fprintf(stderr, "%s\n", (s));                                              \
    exit(c);                                                                   \
  }

#define CHECK_FWRITE1(ret)                                                     \
  {                                                                            \
    if ((ret) != 1)                                                            \
      EXIT_ERROR("fwrite failed", FILE_ERROR);                                 \
  }

#define CHECK_MALLOC(ret)                                                      \
  {                                                                            \
    if ((ret) == NULL)                                                         \
      EXIT_ERROR("malloc failed", MEMORY_ERROR);                               \
  }

typedef struct pcap_hdr_s {
  uint32_t magic_number;  /* magic number */
  uint16_t version_major; /* major version number */
  uint16_t version_minor; /* minor version number */
  int32_t thiszone;       /* GMT to local correction */
  uint32_t sigfigs;       /* accuracy of timestamps */
  uint32_t snaplen;       /* max length of captured packets, in octets */
  uint32_t network;       /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
  uint32_t ts_sec;   /* timestamp seconds */
  uint32_t ts_usec;  /* timestamp microseconds */
  uint32_t incl_len; /* number of octets of packet saved in file */
  uint32_t orig_len; /* actual length of packet */
} pcaprec_hdr_t;

typedef struct vlan_s {
  uint16_t tpid; /* 0x8100, 0x88a8, 0x9100, 0x9200 */

  uint16_t tci; /* 12 lsb are the vlan value (0-4096)
                   3 msb are the priority value (0-7)
                   the 4th is the Drop Eligible Bit */

} vlan_t;

void cleanup(void) { return; }

void set_tpid_value(vlan_t *vlan, uint16_t value) { vlan->tpid = value; }

void set_vid_value(vlan_t *vlan, uint16_t value) {
  vlan->tci |= (value & 0x0fff);
}

void set_prio_value(vlan_t *vlan, uint16_t value) {
  vlan->tci |= (value << 13);
}

void set_dei_value(vlan_t *vlan, uint16_t value) {
  vlan->tci |= (value << 12) & 0x1000;
}

void set_vlan(vlan_t *vlan, uint16_t tpid, uint16_t vid, uint16_t prio,
              uint16_t dei) {
  set_tpid_value(vlan, tpid);
  set_vid_value(vlan, vid);
  set_prio_value(vlan, prio);
  set_dei_value(vlan, dei);
  vlan->tci = htons(vlan->tci);
  vlan->tpid = htons(vlan->tpid);
}

// parse the str and save it into mac
void set_mac(uint8_t *mac, const char *str) {

  // strtok cannot work with const char
  // make a copy on the heap
  char *init = malloc(sizeof(char) * 17);
  memcpy(init, str, sizeof(char) * 17);

  int i = 0;
  char *str_byte = strtok(init, ":");
  while (str_byte != NULL) {
    mac[i++] = (uint8_t)strtol(str_byte, NULL, 16);
    str_byte = strtok(NULL, ":");
  }
  free(init);
}

void print_mac(uint8_t *mac) {
  printf("%2x:%2x:%2x:%2x:%2x:%2x\n", mac[0], mac[1], mac[2], mac[3], mac[4],
         mac[5]);
}

uint8_t pcap_init(FILE **f, const char *filename, pcap_hdr_t *hdr) {
  *f = fopen(filename, "w");
  if (*f == NULL)
    EXIT_ERROR("Could not create file", FILE_ERROR);

  CHECK_FWRITE1(fwrite((const void *)hdr, sizeof(pcap_hdr_t), 1, *f))
  return 0;
}

uint8_t pcap_write(FILE *f, pcaprec_hdr_t *rec, void *data, uint32_t size) {
  if (f == NULL)
    EXIT_ERROR("Attempted to write on NULL descriptor", FILE_ERROR);

  // write the packet header
  CHECK_FWRITE1(fwrite((const void *)rec, sizeof(pcaprec_hdr_t), 1, f))

  // write the packet data
  CHECK_FWRITE1(fwrite((const void *)data, size, 1, f))
}

uint8_t pcap_finalize(FILE *f) { return fclose(f); }

uint8_t data_write_ethernet(uint8_t *data, uint8_t *dst_mac, uint8_t *src_mac,
                            vlan_t **vlans) {

  uint8_t *moving = data;

  memcpy(moving, dst_mac, MAC_ADDRESS_BYTES);
  moving += MAC_ADDRESS_BYTES;

  memcpy(moving, src_mac, MAC_ADDRESS_BYTES);
  moving += MAC_ADDRESS_BYTES;
  int i = 0;
  while (vlans[i] != NULL) {
    memcpy(moving, vlans[i], sizeof(vlan_t));
    moving += sizeof(vlan_t);
    i++;
  }

  uint16_t ip = htons(0x0800);
  memcpy(moving, &ip, sizeof(uint16_t));
}

void populate_global_pcap_header(pcap_hdr_t *hdr) {
  hdr->magic_number = 0xa1b2c3d4;
  hdr->version_major = 2;
  hdr->version_minor = 4;
  hdr->thiszone = 0;
  hdr->sigfigs = 0;
  hdr->snaplen = MAX_FRAME_SIZE;
  hdr->network = 1; // LINKTYPE_ETHERNET
}

void populate_packet_pcap_header(pcaprec_hdr_t *rec, uint32_t size) {
  rec->ts_sec = 0;
  rec->ts_usec = 0;
  rec->incl_len = size;
  rec->orig_len = size;
}

void print_help(void) {
  printf("\nHello.\n");

  printf(\
"\t __  ___  __\n\
\t((_)((_( ((_ \n\
\t ))   _))\n\n"\
	);  

  printf("pgc: Generate pcap files from the command line!\n\n\n");


  printf("(Default values in square brackets)\n\n");

  printf("-f: Set the output file name          [%s]\n", DEFAULT_FILE_NAME);
  printf("-s: Set the source MAC                [%s]\n", DEFAULT_SRC_MAC);
  printf("-d: Set the destination MAC           [%s]\n", DEFAULT_DST_MAC);
  printf("-e: Set the ethertype                 [%s]\n", DEFAULT_ETHERTYPE);
  printf("-v: Set the VLAN ID                   [%s]\n", DEFAULT_VID);
  printf("-p: Set the VLAN Priority             [%s]\n", DEFAULT_PRIO);
  printf("-i: Set the DEI bit                   [%s]\n", DEFAULT_DEI);
  printf("-l: The length of the frame in bytes  [%s]\n", DEFAULT_LENGTH);
  printf("-h: This message\n");

  printf("\n\nMandatory examples:\n");
  printf("\n");
  printf("Ethertype 0x88a8, vlan 222, priority 7, size 256\n");
  printf("./paibuilder -e 0x88a8 -v 222 -p 7 -l 256 -f frame_88a8_222.pcap\n");

  printf("\n\n");
  printf("Ethertype %s, vlan %s, priority %s, size 40 with DEI set\n",
         DEFAULT_ETHERTYPE, DEFAULT_VID, DEFAULT_PRIO);
  printf("./paibuilder -i 1 -l 40 -f frame_8100_100_dei.pcap\n");

  printf("\n\n");
  printf("Report bugs to: me\n");
}

int main(int argc, char *argv[]) {

  FILE *pcap_file;
  uint16_t num_vlans;
  uint8_t src_mac[MAX_FRAME_SIZE];
  uint8_t dst_mac[MAX_FRAME_SIZE];
  uint8_t data[MAX_FRAME_SIZE] = {0};
  vlan_t *vlans[MAX_VLANS] = {0};

  uint8_t insert_vlan;

  // CLI variables
  uint8_t *cli_pcap_name;
  uint8_t *cli_length;
  uint8_t *cli_src_mac;
  uint8_t *cli_dst_mac;
  uint8_t *cli_vid;
  uint8_t *cli_dei;
  uint8_t *cli_ethertype;
  uint8_t *cli_prio;
  int32_t c;

  while ((c = getopt(argc, argv, "hf:s:d:v:i:e:p:l:")) != -1) {
    switch (c) {
    case 'h':
      print_help();
      exit(0);
    case 'f':
      cli_pcap_name = optarg;
      break;
    case 's':
      cli_src_mac = optarg;
      break;
    case 'd':
      cli_dst_mac = optarg;
      break;
    case 'v':
      cli_vid = optarg;
      break;
    case 'i':
      cli_dei = optarg;
      break;
    case 'e':
      cli_ethertype = optarg;
      break;
    case 'p':
      cli_prio = optarg;
      break;
    case 'l':
      cli_length = optarg;
      break;
    default:
      printf("%c %d\n", c, c);
      break;
    }
  }

  // these have to be set in every frame
  if (cli_pcap_name == NULL)
    cli_pcap_name = DEFAULT_FILE_NAME;
  if (cli_length == NULL)
    cli_length = DEFAULT_LENGTH;
  if (cli_src_mac == NULL)
    cli_src_mac = DEFAULT_SRC_MAC;
  if (cli_dst_mac == NULL)
    cli_dst_mac = DEFAULT_DST_MAC;

  uint32_t frame_size = atol(cli_length);

  uint16_t ethertype, vid, prio, dei;
  // these are optional and take default values only if one of them is set
  if (cli_ethertype == NULL && cli_vid == NULL && cli_dei == NULL &&
      cli_prio == NULL) {
    // do not place vlan in the frame
    insert_vlan = 0;
  } else {
    // if even one is present, set the
    // non-present to their default values
    if (cli_ethertype == NULL)
      cli_ethertype = DEFAULT_ETHERTYPE;
    if (cli_vid == NULL)
      cli_vid = DEFAULT_VID;
    if (cli_dei == NULL)
      cli_dei = DEFAULT_DEI;
    if (cli_prio == NULL)
      cli_prio = DEFAULT_PRIO;

    ethertype = strtol(cli_ethertype, NULL, 16);
    vid = atol(cli_vid);
    prio = atol(cli_prio);
    dei = atol(cli_dei);
    insert_vlan = 1;
  }

  pcap_hdr_t *hdr = malloc(sizeof(pcap_hdr_t));
  pcaprec_hdr_t *rec = malloc(sizeof(pcaprec_hdr_t));

  CHECK_MALLOC(hdr);
  CHECK_MALLOC(rec);

  // make everything be zero
  memset(hdr, 0, sizeof(pcap_hdr_t));
  memset(rec, 0, sizeof(pcaprec_hdr_t));

  if (insert_vlan) {
    vlans[0] = malloc(sizeof(vlan_t));
    CHECK_MALLOC(vlans[0]);
    memset(vlans[0], 0, sizeof(vlan_t));
    set_vlan(vlans[0], ethertype, vid, prio, dei);
  }

  populate_global_pcap_header(hdr);
  populate_packet_pcap_header(rec, frame_size);

  // set the basic valuesk
  set_mac(src_mac, cli_src_mac);
  set_mac(dst_mac, cli_dst_mac);

  // paste L2 frame into the `data` array
  data_write_ethernet(data, dst_mac, src_mac, vlans);

  // write everything to the pcap file
  pcap_init(&pcap_file, cli_pcap_name, hdr);
  pcap_write(pcap_file, rec, data, frame_size);
  pcap_finalize(pcap_file);

  // free everything
  free(hdr);
  free(rec);
  uint16_t n = 0;
  while (vlans[n] != NULL)
    free(vlans[n++]);

  return 0;
}
