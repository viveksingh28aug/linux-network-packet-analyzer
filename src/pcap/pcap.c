#include "sniffer/pcap.h"
#include <stdlib.h>
#include <string.h>

static inline uint16_t swap16(uint16_t val)
{
    return (uint16_t)((val << 8) | (val >> 8));
}

static inline uint32_t swap32(uint32_t val)
{
    return ((val >> 24) & 0x000000FF) |
           ((val >> 8)  & 0x0000FF00) |
           ((val << 8)  & 0x00FF0000) |
           ((val << 24) & 0xFF000000);
}

int pcap_reader_open(pcap_reader_t *reader, const char *filepath)
{
    if (!reader || !filepath) return -1;
    memset(reader, 0, sizeof(*reader));

    FILE *fp = fopen(filepath, "rb");
    if (!fp) return -1;

    struct pcap_file_hdr hdr;
    if (fread(&hdr, sizeof(hdr), 1, fp) != 1) {
        fclose(fp);
        return -1;
    }

    if (hdr.magic == PCAP_MAGIC_STANDARD) {
        reader->need_swap = false;
        reader->snaplen = hdr.snaplen;
        reader->linktype = hdr.linktype;
    } else if (hdr.magic == PCAP_MAGIC_SWAPPED) {
        reader->need_swap = true;
        reader->snaplen = swap32(hdr.snaplen);
        reader->linktype = swap32(hdr.linktype);
    } else {
        fclose(fp);
        return -2; /* Unknown PCAP format */
    }

    reader->fp = fp;
    return 0;
}

int pcap_reader_next(pcap_reader_t *reader, uint8_t *buf, size_t max_len,
                     size_t *caplen, size_t *wirelen, struct timeval *ts)
{
    if (!reader || !reader->fp || !buf || !caplen || !wirelen) return -1;

    struct pcap_rec_hdr rec;
    if (fread(&rec, sizeof(rec), 1, reader->fp) != 1) {
        return 0; /* EOF or read error */
    }

    if (reader->need_swap) {
        rec.ts_sec  = swap32(rec.ts_sec);
        rec.ts_usec = swap32(rec.ts_usec);
        rec.caplen  = swap32(rec.caplen);
        rec.wirelen = swap32(rec.wirelen);
    }

    if (ts) {
        ts->tv_sec  = (time_t)rec.ts_sec;
        ts->tv_usec = (suseconds_t)rec.ts_usec;
    }

    *wirelen = rec.wirelen;

    size_t to_read = (rec.caplen < max_len) ? rec.caplen : max_len;
    if (fread(buf, 1, to_read, reader->fp) != to_read) {
        return -1;
    }

    /* If record in file is larger than max_len, skip the overflow bytes */
    if (rec.caplen > to_read) {
        fseek(reader->fp, (long)(rec.caplen - to_read), SEEK_CUR);
    }

    *caplen = to_read;
    return 1; /* Success */
}

void pcap_reader_close(pcap_reader_t *reader)
{
    if (reader && reader->fp) {
        fclose(reader->fp);
        reader->fp = NULL;
    }
}

int pcap_dumper_open(pcap_dumper_t *dumper, const char *filepath, uint32_t snaplen, uint32_t linktype)
{
    if (!dumper || !filepath) return -1;
    memset(dumper, 0, sizeof(*dumper));

    FILE *fp = fopen(filepath, "wb");
    if (!fp) return -1;

    struct pcap_file_hdr hdr;
    hdr.magic = PCAP_MAGIC_STANDARD;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0;
    hdr.sigfigs = 0;
    hdr.snaplen = snaplen ? snaplen : 65536;
    hdr.linktype = linktype ? linktype : DLT_EN10MB;

    if (fwrite(&hdr, sizeof(hdr), 1, fp) != 1) {
        fclose(fp);
        return -1;
    }

    dumper->fp = fp;
    dumper->snaplen = hdr.snaplen;
    dumper->linktype = hdr.linktype;
    return 0;
}

int pcap_dumper_write(pcap_dumper_t *dumper, const uint8_t *buf, size_t caplen, size_t wirelen, const struct timeval *ts)
{
    if (!dumper || !dumper->fp || !buf) return -1;

    struct pcap_rec_hdr rec;
    if (ts) {
        rec.ts_sec  = (uint32_t)ts->tv_sec;
        rec.ts_usec = (uint32_t)ts->tv_usec;
    } else {
        struct timeval now;
        gettimeofday(&now, NULL);
        rec.ts_sec  = (uint32_t)now.tv_sec;
        rec.ts_usec = (uint32_t)now.tv_usec;
    }

    rec.caplen  = (uint32_t)caplen;
    rec.wirelen = (uint32_t)wirelen;

    if (fwrite(&rec, sizeof(rec), 1, dumper->fp) != 1) {
        return -1;
    }
    if (fwrite(buf, 1, caplen, dumper->fp) != caplen) {
        return -1;
    }

    return 0;
}

void pcap_dumper_close(pcap_dumper_t *dumper)
{
    if (dumper && dumper->fp) {
        fclose(dumper->fp);
        dumper->fp = NULL;
    }
}
