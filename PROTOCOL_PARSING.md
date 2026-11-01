# Protocol Parsing Specification & Low-Level Formats

This document provides a comprehensive protocol-by-protocol parsing reference for Layer 2, Layer 3, and Layer 4 protocols supported by the packet analyzer, detailing on-wire bit layouts, field extraction logic, and bitwise operations.

---

## 1. Layer 2: Data Link Layer

### 1.1 Ethernet II Frame Format (DIX Ethernet)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Destination MAC Address (Bytes 0-3)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Dest MAC (Bytes 4-5)        |  Source MAC Address (Bytes 0-1)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Source MAC Address (Bytes 2-5)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           EtherType           |           Payload ...         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Destination & Source MAC:** 6 octets each (`uint8_t[6]`).
- **EtherType:** 16-bit field in network byte order. Converted to host byte order using `ntohs(eth->h_proto)`:
  - `0x0800`: IPv4 (Internet Protocol v4)
  - `0x86DD`: IPv6 (Internet Protocol v6)
  - `0x0806`: ARP (Address Resolution Protocol)
  - `0x8100`: IEEE 802.1Q VLAN Tagged Frame
  - `0x88A8`: IEEE 802.1ad Service VLAN / QinQ

### 1.2 IEEE 802.1Q and IEEE 802.1ad (VLAN / QinQ)

When EtherType is `0x8100` (802.1Q) or `0x88A8` (802.1ad), a 4-byte Tag Header is inserted:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  TPID (0x8100 or 0x88A8)      | PCP |D|          VID          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Inner EtherType        |          Payload ...          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Bitwise Extraction Logic:**
Let `tci = ntohs(vlan_hdr->vlan_tci)`:
- **PCP (Priority Code Point, 3 bits):** `(tci >> 13) & 0x07` (QoS Class of Service, 0-7).
- **DEI / CFI (Drop Eligible Indicator, 1 bit):** `(tci >> 12) & 0x01` (Indicates drop eligibility under congestion).
- **VID (VLAN Identifier, 12 bits):** `tci & 0x0FFF` (VLAN IDs 1 - 4094).
- **QinQ Stacking:** If the inner EtherType is also `0x8100`, the parser recursively peels the inner customer VLAN tag, incrementing offset by 4 bytes.

---

## 2. Layer 3: Network Layer

### 2.1 IPv4 Header Format (RFC 791)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source IP Address                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination IP Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options (Variable Length)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Field Extraction & Validation:**
- **Version:** `iph->version == 4`. Packets with version != 4 are rejected as malformed.
- **IHL (Internet Header Length):** Measured in 32-bit (4-byte) DWORDS. Minimum valid IHL is 5 (20 bytes). Header bytes: `ihl_bytes = iph->ihl * 4`. Options length: `ihl_bytes - 20`.
- **TOS / DSCP / ECN:**
  - **DSCP (6 bits):** `iph->tos >> 2` (Used for DiffServ traffic classification in Cisco routers).
  - **ECN (2 bits):** `iph->tos & 0x03` (Explicit Congestion Notification: ECT(0), ECT(1), CE).
- **Total Length:** `ntohs(iph->tot_len)`. Checked against captured buffer length `caplen`. If `caplen < offset + tot_len`, packet is flagged `is_truncated = true`.
- **Fragmentation:**
  Let `frag_field = ntohs(iph->frag_off)`:
  - **DF (Don't Fragment):** `(frag_field & 0x4000) != 0`
  - **MF (More Fragments):** `(frag_field & 0x2000) != 0`
  - **Fragment Offset:** `(frag_field & 0x1FFF) * 8` (Bytes). If offset > 0, L4 header is not at the start of the payload.
- **Checksum:** 16-bit 1's complement sum over IPv4 header words. Validated with `verify_ipv4_checksum()`.

### 2.2 IPv6 Header Format (RFC 8200)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version| Traffic Class |           Flow Label                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Payload Length        |  Next Header  |   Hop Limit   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                         Source Address                        +
|                           (128 bits)                          |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                      Destination Address                      +
|                           (128 bits)                          |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Field Extraction:**
- **First 32-bit Word:** `flow_word = ntohl(ip6h->ip6_flow)`.
  - **Version (4 bits):** `(ip6h->ip6_vfc >> 4) == 6`.
  - **Traffic Class (8 bits):** `(flow_word >> 20) & 0xFF`.
  - **Flow Label (20 bits):** `flow_word & 0x000FFFFF` (Used by Silicon One for ECMP / LAG hashing).
- **Payload Length:** `ntohs(ip6h->ip6_plen)`.
- **Next Header:** Next protocol or extension header type.
- **Extension Header Processing:**
  - `IPPROTO_HOPOPTS` (0), `IPPROTO_ROUTING` (43), `IPPROTO_DSTOPTS` (60): Length is `(ext_ptr[1] + 1) * 8` bytes.
  - `IPPROTO_FRAGMENT` (44): Fixed 8 bytes length.
  - `IPPROTO_AH` (51): Length is `(ext_ptr[1] + 2) * 4` bytes.

---

## 3. Layer 4: Transport Layer

### 3.1 TCP Header Format (RFC 793)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options and Padding                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Bitwise Flag Decoding:**
Byte offset 13 of TCP header contains 8 control flags:
- `FIN` (0x01): `flags & 0x01`
- `SYN` (0x02): `flags & 0x02`
- `RST` (0x04): `flags & 0x04`
- `PSH` (0x08): `flags & 0x08`
- `ACK` (0x10): `flags & 0x10`
- `URG` (0x20): `flags & 0x20`
- `ECE` (0x40): `flags & 0x40` (ECN Echo)
- `CWR` (0x80): `flags & 0x80` (Congestion Window Reduced)
- **Data Offset:** `tcph->doff * 4` bytes. Minimum valid is 20 bytes (`doff >= 5`).
- **Payload Offset & Length:** `payload_offset = offset + doff * 4`. `payload_len = tcp_total_len - doff * 4`.

### 3.2 UDP Header Format (RFC 768)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |            Checksum           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Length:** `ntohs(udph->len)`. Must be `>= 8` bytes.
- **Checksum:** In IPv4, `0x0000` indicates checksum disabled; in IPv6, checksum calculation is mandatory (RFC 8200). Verified using pseudo-header.

### 3.3 ICMP Header Format (RFC 792)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier          |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Types Supported:**
  - Type 0: Echo Reply
  - Type 3: Destination Unreachable (Codes 0-15: Network Unreachable, Host Unreachable, Port Unreachable, Frag Needed)
  - Type 8: Echo Request (Ping)
  - Type 11: Time Exceeded (TTL expired in transit)
  - Type 12: Parameter Problem
- **Identifier & Sequence:** Decoded for Echo Request/Reply messages (`ntohs(icmph->un.echo.id)`, `ntohs(icmph->un.echo.sequence)`).
