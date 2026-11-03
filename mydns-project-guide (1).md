# mydns.py — CNT 4713 Project 2 (DNS lookup client)

This file has everything needed to work on this project: the assignment, the rules, what the code does now, and what's left to do.

---

## 1. The assignment

Build a simplified **iterative DNS lookup client** in **Python 3** using **UDP sockets**.

- **No DNS libraries.** The program must create its own socket and build and parse DNS messages by hand.
- The program name must be exactly **`mydns`** (file `mydns.py`). Grading is done by an automated script, and the wrong name gets a zero.
- It's run as:
  ```
  python3 mydns.py domain-name root-dns-ip
  ```
  For example: `python3 mydns.py cs.fiu.edu 202.12.27.33`
- Root DNS server IPs are listed at https://www.iana.org/domains/root/servers

### How it must work

1. Send a query for the domain to the root DNS server given on the command line (UDP, port 53).
2. The reply has no answer yet. Instead it lists intermediate name servers (**NS** records) in the **Authority** section, and their IPs (**A** records) in the **Additional** section.
3. Pick one intermediate server that has an IP in the Additional section, and send it the same query.
4. Repeat until a reply has one or more **A** records for the domain in the **Answers** section. Then stop.

Only two record types need to be understood:
- **NS (type 2):** an intermediate name server. Look up its IP in the Additional section.
- **A (type 1):** an IPv4 address.

IPv6 (AAAA records) can be ignored.

For every step, the program must print the content of the reply and the server chosen to query next.

The RFC (https://www.ietf.org/rfc/rfc1035.txt) Section 4 explains the message format. **Section 4.1.4 (message compression)** matters most: names can contain pointers that jump back to an earlier spot in the message.

### Grading

| Item | % |
|---|---|
| Send query to root DNS server | 10 |
| Parse reply from root DNS server | 15 |
| Display server reply content | 15 |
| Extract intermediate DNS server IP | 15 |
| Send query to intermediate servers | 15 |
| Parse reply from intermediate servers | 15 |
| Display IPs for queried domain name | 15 |

### Submission

- `mydns.py`, and only `.py` files
- `readme.txt` with: member names and IDs, and "Language used: Python3". Python needs no compile instructions.

### Sample output from the PDF (format to match)

```
$ ./mydns cs.fiu.edu 202.12.27.33

----------------------------------------------------------------
DNS server to query: 202.12.27.33
Reply received. Content overview:
0 Answers.
6 Intermediate Name Servers.
7 Additional Information Records.
Answers section: 
Authority Section:
Name : edu Name Server: l.edu-servers.net
Name : edu Name Server: a.edu-servers.net
Name : edu Name Server: f.edu-servers.net
Name : edu Name Server: c.edu-servers.net
Name : edu Name Server: g.edu-servers.net
Name : edu Name Server: d.edu-servers.net
Additional Information Section:
Name : a.edu-servers.net IP : 192.5.6.30
Name : c.edu-servers.net IP : 192.26.92.30
Name : d.edu-servers.net IP : 192.31.80.30
Name : f.edu-servers.net IP : 192.35.51.30
Name : g.edu-servers.net IP : 192.42.93.30
Name : l.edu-servers.net IP : 192.41.162.30
Name : g.edu-servers.net 
----------------------------------------------------------------
DNS server to query: 192.5.6.30
Reply received. Content overview:
0 Answers.
5 Intermediate Name Servers.
5 Additional Information Records.
Answers section: 
Authority Section:
Name : fiu.edu Name Server: ns.fiu.edu
Name : fiu.edu Name Server: ns3.fiu.edu
Name : fiu.edu Name Server: ns1.fiu.edu
Name : fiu.edu Name Server: drdns.fiu.edu
Name : fiu.edu Name Server: ns4.fiu.edu
Additional Information Section:
Name : ns.fiu.edu IP : 131.94.205.10
Name : ns3.fiu.edu IP : 131.94.226.10
Name : ns1.fiu.edu IP : 131.94.7.220
Name : drdns.fiu.edu IP : 131.94.69.36
Name : ns4.fiu.edu IP : 131.95.205.12
----------------------------------------------------------------
DNS server to query: 131.94.205.10
Reply received. Content overview:
0 Answers.
4 Intermediate Name Servers.
4 Additional Information Records.
Answers section: 
Authority Section:
Name : cs.fiu.edu Name Server: goedel.cs.fiu.edu
Name : cs.fiu.edu Name Server: sagwa-ns.cs.fiu.edu
Name : cs.fiu.edu Name Server: offsite.cs.fiu.edu
Name : cs.fiu.edu Name Server: zorba-ns.cs.fiu.edu
Additional Information Section:
Name : offsite.cs.fiu.edu IP : 131.94.68.228
Name : sagwa-ns.cs.fiu.edu IP : 131.94.134.129
Name : zorba-ns.cs.fiu.edu IP : 131.94.134.130
Name : goedel.cs.fiu.edu IP : 131.94.133.43
----------------------------------------------------------------
DNS server to query: 131.94.68.228
Reply received. Content overview:
1 Answers.
6 Intermediate Name Servers.
4 Additional Information Records.
Answers section: 
Name : cs.fiu.edu IP: 131.94.130.238
Authority Section:
Name : cs.fiu.edu Name Server: zorba-ns.v6.cs.fiu.edu
Name : cs.fiu.edu Name Server: goedel.cs.fiu.edu
Name : cs.fiu.edu Name Server: offsite.cs.fiu.edu
Name : cs.fiu.edu Name Server: sagwa-ns.cs.fiu.edu
Name : cs.fiu.edu Name Server: sagwa-ns.v6.cs.fiu.edu
Name : cs.fiu.edu Name Server: zorba-ns.cs.fiu.edu
Additional Information Section:
Name : goedel.cs.fiu.edu IP : 131.94.133.43
Name : offsite.cs.fiu.edu IP : 131.94.68.228
Name : sagwa-ns.cs.fiu.edu IP : 131.94.134.129
Name : zorba-ns.cs.fiu.edu IP : 131.94.134.130
```

The line `Name : g.edu-servers.net ` with no IP in the first step is the 7th additional record, which is IPv6 in the PDF's run. The current code skips IPv6 records instead of printing a name with no IP. Either is acceptable, since the assignment says IPv6 can be ignored.

Note the exact spacing: `Answers section: ` has a trailing space, Answers use `IP:` (no space before the colon), and Additional uses `IP :` (with a space).

The server names, counts, and IPs come from live DNS, so they'll differ from the PDF. Only the **format** has to match.

---

## 2. Rules for editing this code

- **The course skeleton must stay.** Don't rewrite or remove skeleton code. Only add to it. The skeleton functions `create_query`, `parse_unsigned_int`, `parse_name`, the command-line handling, and all the RFC comment diagrams stay as they are.
- If something from the skeleton needs to stop running, **comment it out** with `#`. Don't delete it.
- Keep changes targeted. Explain what each change does.

---

## 3. What has already been added to the skeleton

The code currently works end to end. These are the additions, all marked `# added` in the file.

**a. Type constants**, under the imports:
```python
TYPE_A = 1
TYPE_NS = 2
```

**b. Two new functions after `parse_name`:**
- `parse_ip(index, response)` turns 4 bytes into a string like `131.94.205.10`.
- `parse_rr(index, response)` parses one resource record (RFC 4.1.3): NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA. For A records, RDATA is read as an IP. For NS records, it's read as a name with `parse_name`, which handles compression. It always returns `index + rdlength`, so record types it doesn't understand (like AAAA) are skipped cleanly.

**c. Added to the end of `parse_response`**, after the skeleton's `QCLASS` print:
- reads ANCOUNT, NSCOUNT, and ARCOUNT from header bytes 6–11
- loops `parse_rr` over the Answers, Authority, and Additional sections. The skeleton's code has already moved `index` past the header and question, so the loops start in the right place.
- prints the reply in the sample's format
- `return answers, authority, additional`

**d. At the bottom of the file:**
- added `print('-' * 64)` and `print(f'DNS server to query: {root_dns_ip}')` before the first `sendto`
- changed `parse_response(response)` to `answers, authority, additional = parse_response(response)`. This is the only edited skeleton line.
- added a `while` loop: as long as there are no A records in the answers, it builds a map of NS name → IP from the Additional section, picks the first NS in Authority that has an IP, prints the divider and `DNS server to query: <ip>`, sends the same query there, and parses the new reply. If no NS has an IP, it prints a message and stops.

The skeleton's variable `socket = socket(AF_INET, SOCK_DGRAM)` was kept as is, even though it shadows the `socket` class name.

---

## 4. Current output (works)

Running `python3 mydns.py cs.fiu.edu 202.12.27.33` goes root → `.edu` server → FIU name server → `offsite.cs.fiu.edu`, and ends with:

```
Answers section: 
Name : cs.fiu.edu IP: 131.94.130.106
```

`.106` differs from the PDF's `.238` because FIU changed the IP. Verify with `nslookup cs.fiu.edu 8.8.8.8`.

Some counts are bigger than the number of IPs printed (for example, "14 Additional Information Records" with 13 IPs listed). The extra records are IPv6, which the assignment allows skipping. The PDF's sample shows the same thing.

---

## 5. Task left to do: make the output match the sample exactly

Each step still prints the skeleton's debug lines, which aren't in the sample output:

```
----- parse response -----
Header section [RFC 4.1.1. Header section format]
ID: 1
QDCOUNT: 1
...
QCLASS: 1
```

These prints were in the skeleton to show that header and question parsing works. They aren't part of the required output.

**Inside `parse_response`, comment out (don't delete) exactly these 11 lines**, keeping their indentation:

```python
print('----- parse response -----')
print('Header section [RFC 4.1.1. Header section format]')
print(f'ID: {num}')
print(f'QDCOUNT: {num}')
print(f'ANCOUNT: {num}')
print(f'NSCOUNT: {num}')
print(f'ARCOUNT: {num}')
print('Question section [RFC 4.1.2. Question section format]')
print(f'QNAME: {name}')
print(f'QTYPE: {num}')
print(f'QCLASS: {num}')
```

Example: `print(f'ID: {num}')` becomes `# print(f'ID: {num}')`

Leave the parsing lines next to them active (`num, index = parse_unsigned_int(...)`, `index += 2`, `name, index = parse_name(...)`). They move `index` through the message, and the record parsing after them depends on that.

### Check after the change

1. Run `python3 mydns.py cs.fiu.edu 202.12.27.33`.
2. Each step should print only the divider, `DNS server to query: ...`, `Reply received. Content overview:`, the three counts, and the three sections, the same as the sample.
3. The last step should show the A record for `cs.fiu.edu`.
4. Confirm the IP with `nslookup cs.fiu.edu 8.8.8.8`.

---

## 6. Still to do before submitting

- Write `readme.txt` with member names and IDs, and "Language used: Python3".
- Optional: test with another domain (for example `python3 mydns.py www.fiu.edu 202.12.27.33`) to make sure it works beyond the example.
