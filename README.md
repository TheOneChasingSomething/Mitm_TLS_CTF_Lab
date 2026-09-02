# "HTTPS Security" lab — TLS challenge laboratory

> 🇬🇧 English below · 🇫🇷 Version française plus bas.

**Context**: a hands-on lab on HTTPS transport security, structured as eleven
*capture-the-flag* challenges. Two **warm-up** challenges (OpenSSL, Scapy) equip
the learner, one **cleartext interception** challenge (MITM HTTP) establishes the
network-attacker posture, then eight challenges defeat, in a controlled way, a
distinct property of TLS security — so the learner experimentally rebuilds the
link between *theoretical guarantee* and *implementation condition*.

> ⚠️ **Warning.** This lab ships deliberately vulnerable TLS stacks (RSA key
> exchange without PFS, 512-bit export DHE, SSL 3.0, TLS 1.0/CBC, OpenSSL
> 1.0.1f). It must be run exclusively on an isolated network, never routable to a
> production network or to the Internet (see §8).

> 📘 The **instructor answer key** (*mainstream tools* **then** *Scapy* resolution
> for each challenge) is not provided at the moment.

---

## 1. Learning objectives

By the end of the lab, the learner should be able to:

1. **operate the basic tooling**: build, inspect and verify an X.509 certificate
   by hand with OpenSSL (ASN.1 walk); sniff, dissect, craft and send packets with
   Scapy [18];
2. distinguish the three guarantees of a TLS channel — **confidentiality**,
   **integrity**, **peer authentication** — and show they are *separable* (a
   channel may encrypt without authenticating; a channel may offer no guarantee
   at all if there is no TLS) [5, 8];
3. tie each vulnerability to the faulty layer: identity (PKI), secret management,
   **forward secrecy** (absent or *imperfect*), protocol negotiation, or
   implementation;
4. take up a **man-in-the-middle** position (ARP poisoning, RFC 826 [15]) and
   wield public tooling (bettercap, mitmproxy, `openssl s_client`,
   Wireshark/tshark, `nmap --script ssl-*`, `testssl.sh`);
5. state, for each attack, the corresponding **normative countermeasure** (RFC
   5280 validation, ECDHE/PFS ephemeral exchanges, DH groups ≥ 2048 bits, HSTS
   RFC 6797, `TLS_FALLBACK_SCSV` RFC 7507, 1/n-1 splitting and explicit IV
   RFC 4346, OpenSSL upgrade) [4, 6, 9, 17, 19].

## 2. Threat model and architecture

The chosen model is the **active network attacker** (Dolev–Yao) placed between a
victim-client and a server: it can read, rewrite, replay and inject packets, but
holds *a priori* no cryptographic secret. Challenges C6 and C7 enrich this model:
C6 adds **deferred compromise** (record now, obtain the key later); C7 (Logjam)
adds the **active downgrade** of an ephemeral exchange to a group so weak that
computing the discrete logarithm becomes feasible after an **amortized
precomputation** on the shared prime [8, 19].

Structuring design principle: **the application portal is never broken at the
application level**. The vulnerability always lies in the *transport* layer placed
in front of it (TLS termination by nginx/apache/openssl), or in its absence (MITM
HTTP). This separation isolates the variable under study and avoids conflating a
web flaw (out of scope) with a TLS flaw (the subject of the lab).

```
          Isolated lab network (172.28.0.0/24)
  ┌───────────────┐        MITM        ┌────────────────────────────┐
  │ victim-client │◄────attacker──────►│  target Cx: TLS front-end  │
  │  (careless)   │                    │  VULNERABLE  →  portal     │
  └───────┬───────┘                    └──────────────┬─────────────┘
          │ armed with (dest IP)                      │ cleartext proxy
          └───────────────  Flask portal  ────────────┘
              (encrypted flag feed · start · verify)
```

Components (see `docker-compose.yml`):

| Role | Container | Function |
|------|-----------|----------|
| Portal | `portal` | Serves the encrypted flag, arms the victim-client, verifies flags |
| Victim | `victim-client` | Emits the careless traffic to be intercepted |
| Targets | `c1`…`c11` | Vulnerable front-ends (or Scapy beacon), one per challenge |

The portal refuses any destination IP outside `LAB_CIDR`: it cannot be diverted
into a generic attack launcher (validation in `app/app.py`). The warm-ups (C1
OpenSSL, C2 Scapy) are *direct* interactions with the target and do not involve
the victim-client.

## 3. Challenge → defeated layer map

| # | Challenge | Layer / skill | Guarantee voided | Ref. |
|---|-----------|---------------|------------------|------|
| 1 | OpenSSL warm-up | X.509 tooling (ASN.1) | — (training) | [4] |
| 2 | Scapy warm-up | Network tooling (sniff/craft) | — (training) | [15, 18] |
| 3 | MITM against HTTP | No encrypted transport | Confidentiality (total) | [15] |
| 4 | Self-signed cert + MITM | PKI identity | Authentication | [4] |
| 5 | Private-key leak | Secret management (app-layer RSA-OAEP) | Persistent confidentiality | — |
| 6 | No forward secrecy | RSA key exchange (no ephemeral) | *Retroactive* confidentiality | [5, 8] |
| 7 | Logjam (export DHE) | 512-bit DH group + downgrade | Confidentiality (*imperfect* FS) | [19, 20] |
| 8 | SSL stripping | Transport policy | Confidentiality (via downgrade) | [6, 7] |
| 9 | POODLE (SSLv3/CBC) | Negotiation + CBC mode | Confidentiality | [9, 10] |
| 10 | BEAST (TLS 1.0/CBC) | Predictable IV (chained CBC) | Confidentiality (chosen-plaintext) | [13, 14, 16] |
| 11 | Heartbleed | Implementation (RFC 6520) | Confidentiality (memory) | [3, 11] |

> **C6 → C7 — the same lesson, two degrees.** C6: *no* ephemeral (RSA exchange) →
> leaking the long-term key decrypts the entire past. C7: the ephemeral exists
> (DHE) but is **downgraded** to a 512-bit group whose discrete logarithm is
> precomputable — forward secrecy is *present but imperfect* (hence the title of
> the founding paper, "Imperfect Forward Secrecy" [19]). The common defense:
> **robust** ephemerals (ECDHE, or DH ≥ 2048 bits).

## 4. Building the images (Packer)

Two routes, at the instructor's discretion:

**(a) Packer → Docker** — the portal image built by immutable *provisioning*
(`packer/portal.pkr.hcl`). This "immutable image" approach [1, 2] guarantees
bit-for-bit reproducibility independent of a local `docker build`:

```sh
cd packer && packer init . && packer build -only='docker.*' .
```

**(b) Packer → QEMU** — baking a **self-contained VM** carrying the whole lab
(`packer/lab-vm.pkr.hcl`). The ideal classroom deliverable: a single `qcow2`
handed to each student, with no runtime network dependency (guaranteed
isolation):

```sh
cd packer && packer init . && packer build -only='qemu.*' .
# → output-lab-vm/tls-lab.qcow2
```

> `-only` targets the build's **address** (`<type>.<source>`, e.g.
> `docker.docker.portal`); the patterns `'docker.*'` / `'qemu.*'` spare you from
> spelling it out.
>
> The VM needs a `packer/http/user-data` (cloud-init) with a valid password hash:
> generate it via `mkpasswd -m sha-512` and replace the sample `passwd:`
> parameter.

## 5. Deploying the lab

This section details how to choose the right installation mode, the prerequisites, and the specific commands for each context.

### 5.1 How to choose your installation type?

| Context | Recommended Mode | Architecture |
| :--- | :--- | :--- |
| **Personal Learning / Dev** | `local_docker` | All containers run locally. |
| **Cloud / Remote Lab** | `cloud_standalone` | **You run Ansible from your machine**, but the lab (Docker containers) runs on a remote VM (CloudStack/AWS). |
| **Classroom (Physical PCs)** | `baremetal_classroom` | Teacher's server runs the portal; students' PCs run the targets. |
| **Anti-Cheat / Proctored Exam** | `baremetal_centralized` | Everything runs on a central server; students connect via isolated SSH sessions. |

### 5.2 Prerequisites


To deploy the lab on a Cloud VM from your machine:

1.  **On your machine (Control Node):**
    *   **Python 3.9+** installed.
    *   **Ansible** installed (`pip install ansible`).
    *   **SSH Key**: Your private key (e.g., `~/.ssh/id_ed25519`) must be configured to access the VM.

2.  **On the Target VM (Cloud Instance):**
    *   **SSH Access**: Port 22 must be open in the Security Group.
    *   **Python**: Usually pre-installed on Linux images (required for Ansible modules).
    *   **No Docker or Ansible needed**: Ansible will install Docker automatically during the deployment.

**Verification Step:**
Before running the deployment, ensure you can connect manually from your machine:
```bash
ssh -i ~/.ssh/id_ed25519 root@YOUR_VM_IP
```

### 5.3 Configuring Ansible Inventory (`ansible/inventory.ini`)

For the **Cloud Standalone** mode, you must configure the connection from your machine to the remote VM.

1.  Open `ansible/inventory.ini`.
2.  Locate the `[cloud_vm]` section.
3.  **Uncomment** the `vm_target` line and fill in your details:
    ```ini
    [cloud_vm]
    # Replace with your Cloud VM IP
    vm_target ansible_host=YOUR_VM_IP ansible_port=22 ansible_user=root ansible_ssh_private_key_file=~/.ssh/id_ed25519
    ```
4.  Ensure the `[teacher:children]` section points to `cloud_vm`:
    ```ini
    [teacher:children]
    cloud_vm
    ```

**Key Variables:**
*   `ansible_host`: The **Public IP** or **Private IP** of your Cloud instance VM.
*   `ansible_user`: The user account on the VM (e.g., `root`, `ubuntu`, `centos`).
*   `ansible_ssh_private_key_file`: Path to your **local** private key (on your machine) that matches the public key injected in the VM.

### 5.4 Installation Commands by Type

#### A. Local Docker Mode (Development)
Run everything locally.
```bash
make local_up
```


#### B. Cloud Standalone (local machine -> Remote VM)

**This is the recommanded mode.** You execute the command from your machine. Ansible connects to the remote VM, installs Docker, and deploys the lab there.

1. **Configure Inventory**: Set up `ansible/inventory.ini` as described in §5.3.
2. **Run Deployment**:
	`make cloud_standalone`
	*What happens:*
	- Ansible connects to your VM via SSH.
		- It runs `init.yml` to install Docker, Git, and prepare the environment.
		- It runs `standalone.yml` to launch the Docker containers (Portal, Targets, Victim).
3. **Access the Lab**: Once finished, open your browser to `http://<YOUR_VM_IP>:5000`.

#### C. Classroom Mode (Fleet of Workstations)

Deploy on physical machines in a classroom network.

`make classroom`

#### D. Centralized Anti-Cheat Mode

Strict isolation per student on a central server.

`make generate-keys make deploy_baremetal_centralized`

### 5.5 Debugging & Troubleshooting

If `make cloud_standalone` fails:

1. **Test SSH Connectivity First**: Before running Ansible, ensure you can connect manually from your machine:
	`ssh -i ~/.ssh/id_ed25519 root@YOUR_VM_IP`
	If this fails, check your Cloud instance Security Group (allow port 22) and your firewall.
2. **Check Ansible Logs**: Run with verbose mode to see exactly where it fails:
	`cd ansible && ansible-playbook init.yml -i inventory.ini -vvv`
3. **Verify Docker on Target**: If the installation seems stuck, SSH into the VM and check if Docker was installed:
	`ssh -i ~/.ssh/id_ed25519 root@YOUR_VM_IP docker --version docker compose ps`
4. **Firewall Issues**: Ensure your Cloud instance **Security Group** allows inbound traffic on:
	- Port **22** (SSH for Ansible)
		- Port **5000** (Portal)
		- Ports **8441-8453** (Challenges)

## 6. Detailed walkthrough per challenge

Each section follows the same template: *context → exploitation chain → normative
countermeasure*. The complete solutions (public tools **and** Scapy) are in
`SOLUTIONS.md`.

### C1 — OpenSSL warm-up (10 pts)
- **Goal**: retrieve the target's self-signed certificate (`openssl s_client`),
  inspect it (`openssl x509 -text`), then **verify its signature by hand**
  (`asn1parse` walk, BIT STRING extraction, `rsautl -verify`, comparison to the
  TBSCertificate digest). The flag is embedded in the certificate's *OU* field.
- **Teaching**: manually unfold what `openssl verify` automates; understand the
  ASN.1 structure and the signature ↔ body link (RFC 5280 [4]).

### C2 — Scapy warm-up (10 pts)
- **Goal**: sniff the UDP/8452 beacon (`sniff(filter="udp port 8452")`), read the
  instruction, **craft** the magic datagram and **send** it (`sr1`); the target
  then replies with the flag.
- **Teaching**: the three Scapy gestures — sniff, layer dissection,
  craft/send — the foundation of the following MITM challenges [18].

### C3 — MITM against cleartext HTTP (20 pts)
- **Transport**: cleartext HTTP (port 8453), **no TLS**.
- **Exploitation**: ARP poisoning (`arp_spoof.py` or bettercap) between victim and
  target, then sniffing (`sniff_http_flag.py` / tcpdump); the flag travels in the
  clear.
- **Teaching**: without transport encryption, confidentiality is nil; active
  interception (RFC 826 [15]) is enough.
- **Countermeasure**: mandatory HTTPS + permanent redirect + HSTS (see C8).

### C4 — Self-signed certificate & MITM (15 pts)
- **Transport**: TLS 1.2, self-signed certificate, *not validated by the client*.
- **Exploitation**: ARP-spoof the victim-client; transparent interception
  (`bettercap`/`mitmproxy`); the attacker presents their own self-signed
  certificate, which the victim accepts (validation disabled), and reads the flag.
- **Teaching**: encryption without **peer authentication** offers no protection
  against a MITM; trust rests on validating the certificate chain [4].
- **Countermeasure**: strict RFC 5280 validation (chain, SAN, revocation);
  pinning where appropriate.

### C5 — Private-key leak (20 pts)
- **Transport**: healthy TLS, but the portal's RSA private key is exposed under
  `/.well-known/backup/server.key`. The flag is published **RSA-OAEP**-encrypted
  by `/c/5/flag-feed`.
- **Exploitation**:
  ```sh
  curl -k https://TARGET:8442/.well-known/backup/server.key -o server.key
  curl -k https://TARGET:8442/c/5/flag-feed | jq -r .ciphertext_b64 | base64 -d > flag.bin
  openssl pkeyutl -decrypt -inkey server.key \
     -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in flag.bin
  ```
- **Teaching**: compromising a long-term key voids the confidentiality of
  everything it protects. Here the protection is *application-level* (a blob); C6
  shows the same logic at the *transport* level.
- **Countermeasure**: compartmentalize secrets, restrictive permissions,
  rotation, no secret under a served directory tree.

### C6 — No forward secrecy / RSA key exchange (25 pts)
- **Transport**: TLS 1.2 negotiating an **RSA key exchange** (`kRSA` suites like
  `TLS_RSA_WITH_AES_128_CBC_SHA`; no ECDHE/DHE). The pre-master secret is
  encrypted under the server's RSA public key and carried in the
  ClientKeyExchange. The server's private key is exposed under
  `/.well-known/backup/server.key`.
- **Exploitation** (*after-the-fact* decryption):
  1. **record** the victim's TLS traffic: `tcpdump -i eth0 -w cap.pcap
     'host TARGET and port 8447'` (from a MITM position if needed, cf.
     `arp_spoof.py`);
  2. **leak** the key: `curl -k
     https://TARGET:8447/.well-known/backup/server.key -o server.key`;
  3. **decrypt** offline: Wireshark → *Preferences ▸ Protocols ▸ TLS ▸ RSA keys
     list* (add `server.key`), or
     `tshark -r cap.pcap -o "tls.keys_list:TARGET,8447,http,server.key" -Y http`.
     The flag appears in the clear in the decrypted HTTP response.
- **Teaching**: without an ephemeral, the long-term key is enough to recompute
  *all* captured past sessions. **Forward secrecy** (ECDHE) breaks this link: each
  session derives from an ephemeral secret destroyed after use, which no later
  leak of the long-term key can reconstruct [5, 8].
- **Countermeasure**: enforce **ECDHE** suites (forward secrecy); in TLS 1.3
  static RSA key exchange is simply removed.

### C7 — Logjam / export DHE (25 pts)
- **Transport**: TLS 1.2 accepting **EXPORT-grade DHE** suites — a **512-bit**
  Diffie-Hellman group (`EXP-EDH-RSA-DES-CBC-SHA`). No protection against
  *downgrade*. The flag is carried by the `SESSIONFLAG` cookie.
- **Exploitation**:
  1. **detect**: `testssl.sh --logjam TARGET:8448`, `nmap --script
     ssl-dh-params -p 8448 TARGET`, or `openssl s_client -connect TARGET:8448
     -cipher EXP` (a 512-bit session establishes);
  2. from a **MITM** position, force the ClientHello downgrade to the DHE_EXPORT
     suite (the server answers with its 512-bit group);
  3. **break** the 512-bit group's discrete logarithm — costly once, but
     **amortized** because the same prime is shared by countless servers
     (precomputation), yielding the ephemeral secret then decryption of the
     session and reading of the cookie [19, 20].
- **Teaching**: an *ephemeral* exchange only ensures forward secrecy if the group
  is **robust**. An export group (512 bits), or even a shared 1024-bit group, is
  within reach of a precomputation (Logjam): FS becomes *imperfect*. This is the
  "DH" counterpart of C6's "RSA".
- **Countermeasure**: disable all EXPORT suites; enforce DH groups
  **≥ 2048 bits** (or unique per server); prefer ECDHE. On the client, reject DHE
  groups < 1024 bits (the browsers' Logjam fix) [19].

### C8 — SSL stripping (20 pts)
- **Transport**: service reachable in the clear (port 80), **no HSTS**, hardcoded
  `http://` link.
- **Exploitation**: MITM + HTTPS→HTTP downgrade (`bettercap` caplet `hstshijack`,
  or `sslstrip2`); the flag then travels in the clear and is captured.
- **Teaching**: Marlinspike's attack [7] exploits the cleartext *bootstrap*. The
  fix is to make HTTPS **mandatory and remembered** on the client side.
- **Countermeasure**: `Strict-Transport-Security` (HSTS, RFC 6797) with
  `includeSubDomains` and listing on the *preload list* [6].

### C9 — POODLE / SSL 3.0 (25 pts)
- **Transport**: SSL 3.0 accepted, **CBC** suites, `TLS_FALLBACK_SCSV` absent →
  forced fallback possible. The flag is carried by the `SESSIONFLAG` cookie.
- **Exploitation**: force the SSLv3 fallback (`openssl s_client -ssl3`); from a
  MITM position, exploit SSL 3.0's **CBC padding oracle** to reconstruct the
  cookie byte by byte [9, 10].
- **Teaching**: SSL 3.0 does not specify the CBC padding content, making its
  verification exploitable as an oracle. An obsolete protocol stays dangerous as
  long as a downgrade is possible.
- **Countermeasure**: disable SSL 3.0; enforce `TLS_FALLBACK_SCSV` (RFC 7507)
  against downgrades [9].

### C10 — BEAST / TLS 1.0 CBC (25 pts)
- **Transport**: TLS 1.0 only, **CBC** suites. In TLS 1.0, a record's IV is the
  previous record's last ciphertext block: it is **predictable**. The flag is
  carried by the `SESSIONFLAG` cookie.
- **Exploitation**: confirm (`openssl s_client -tls1`, `testssl.sh`,
  `nmap --script ssl-enum-ciphers`); from a MITM position (ARP poisoning,
  `arp_spoof.py`), mount the **adaptive chosen-plaintext** attack (blockwise
  chosen-boundary) that aligns the block boundary and guesses the cookie byte by
  byte [13, 14, 16].
- **Teaching**: a predictable IV turns CBC encryption into a chosen-plaintext
  oracle. This is a **protocol-design** weakness (TLS 1.0), distinct from POODLE's
  *padding* oracle.
- **Countermeasure**: ban TLS 1.0; failing that, **1/n-1 record splitting** or
  AEAD suites (AES-GCM). TLS 1.1+ structurally closes BEAST with an explicit
  per-record IV (RFC 4346 [17]).

### C11 — Heartbleed / OpenSSL 1.0.1f (20 pts)
- **Transport**: OpenSSL 1.0.1f, **Heartbeat** extension (RFC 6520) with no check
  of the announced length. The flag resides in the process memory.
- **Exploitation**:
  ```sh
  nmap -p 8445 --script ssl-heartbleed TARGET     # detection
  # then RFC 6520 PoC: Heartbeat request with an oversized payload_length
  # → out-of-bounds read up to 64 KB, where the flag sits.
  ```
- **Teaching**: a single unchecked length exposes arbitrary memory blocks (keys,
  cookies, data) — the canonical illustration of an implementation vulnerability,
  distinct from a protocol weakness [3, 11].
- **Countermeasure**: upgrade OpenSSL ≥ 1.0.1g; regenerate potentially exposed
  secrets.

## 7. Scoring

| Challenge | Points | Skill assessed |
|-----------|:------:|----------------|
| C1 OpenSSL warm-up | 10 | X.509 / ASN.1 manipulation |
| C2 Scapy warm-up | 10 | Sniff / craft / send |
| C3 MITM HTTP | 20 | Active interception (ARP) |
| C4 Self-signed cert | 15 | PKI validation |
| C5 Key leak | 20 | Secret management (app-level) |
| C6 Forward secrecy (RSA exchange) | 25 | After-the-fact decryption / PFS |
| C7 Logjam (export DHE) | 25 | DH downgrade + precomputed discrete log |
| C8 SSL stripping | 20 | MITM defense / HSTS |
| C9 POODLE | 25 | CBC oracle / obsolescence |
| C10 BEAST | 25 | Predictable IV / chosen-plaintext |
| C11 Heartbleed | 20 | Memory disclosure |
| **Total** | **215** | |

## 8. Precautions, ethics and isolation

1. **Absolute isolation**: non-routable network; `internal: true` recommended.
2. **Scope**: the portal only arms the victim-client toward private IPs in
   `LAB_CIDR` — no attack outside the lab is possible from the app.
3. **Network capabilities**: the Scapy target (C2) and the attack hosts require
   `NET_RAW`/`NET_ADMIN`; grant them only within the isolated network.
4. **Legal framing**: controlled environment, documented pedagogical consent;
   interception techniques are lawful only on infrastructure you control.
5. **Life cycle**: destroy the vulnerable instances after the lab (`make clean`);
   keep "clean" snapshots.
6. **Debrief**: each challenge ends with the statement of its countermeasure.

### Reproducibility caveats (obsolete protocols)

Legacy protocols are progressively removed from recent stacks:

- **C6 (RSA exchange)**: `kRSA` suites are deprecated; re-enabled via
  `@SECLEVEL=1` in `ssl_ciphers`. Wireshark decrypts traffic with the private key
  **only** for the RSA exchange (impossible with ECDHE) — which is precisely the
  teaching point.
- **C7 (Logjam)**: **EXPORT** suites were removed from OpenSSL ≥ 1.0.2g. The
  target is therefore built on `ubuntu:14.04` (OpenSSL 1.0.1f, which still ships
  them). The **512-bit discrete-log break** is not run in class: it relies on a
  precomputation/PoC for the known group (that is the *whole* logic of Logjam —
  the precomputation is amortized). The gradable exercise is **detection** and
  **demonstrating the downgrade**; full decryption is provided turnkey by the
  instructor.
- **C9 (SSLv3)**: pinned `httpd:2.4.29` image.
- **C10 (TLS 1.0)**: re-enabled via `targets/beast/openssl-lab.cnf` (`MinProtocol=
  TLSv1`, `@SECLEVEL=0`). A legacy base otherwise.
- **C11 (Heartbleed)**: OpenSSL 1.0.1f compiled from the official archive.

These targets were **not** built/run in the preparation environment (network
disabled): validate the `docker build` on a tooled host before the session.

## 9. Reproducibility and anti-cheat

Flags are loaded from the environment (`FLAG_C1`…`FLAG_C11`), propagated
consistently to the portal **and** the corresponding target via `docker-compose`.
To generate a unique instance per cohort or per student, set a `.env` then
`docker compose up -d --build --force-recreate`. Verification is zero-disclosure
(constant-time comparison on a SHA-256 digest, cf. `challenges.py`).

## 10. References

[1] K. Morris, *Infrastructure as Code*, 2nd ed., O'Reilly, 2020.
[2] HashiCorp, *Packer Documentation — Immutable Machine Images*, docs.packer.io.
[3] R. Seggelmann, M. Tuexen, M. Williams, "Transport Layer Security (TLS) and
    Datagram TLS (DTLS) Heartbeat Extension", **RFC 6520**, IETF, 2012.
[4] D. Cooper *et al.*, "Internet X.509 Public Key Infrastructure Certificate
    and CRL Profile", **RFC 5280**, IETF, 2008.
[5] T. Dierks, E. Rescorla, "The TLS Protocol Version 1.2", **RFC 5246**, 2008.
[6] J. Hodges, C. Jackson, A. Barth, "HTTP Strict Transport Security (HSTS)",
    **RFC 6797**, IETF, 2012.
[7] M. Marlinspike, "New Tricks for Defeating SSL in Practice", *Black Hat DC*,
    2009.
[8] E. Rescorla, "The Transport Layer Security (TLS) Protocol Version 1.3",
    **RFC 8446**, IETF, 2018.
[9] B. Möller, A. Langley, "TLS Fallback Signaling Cipher Suite Value (SCSV) for
    Preventing Protocol Downgrade Attacks", **RFC 7507**, IETF, 2015.
[10] B. Möller, T. Duong, K. Kotowicz, "This POODLE Bites: Exploiting the SSL
    3.0 Fallback", Google, 2014. (CVE-2014-3566)
[11] MITRE, "CVE-2014-0160 (Heartbleed)", *Common Vulnerabilities and
    Exposures*, 2014.
[12] A. Freier, P. Karlton, P. Kocher, "The Secure Sockets Layer (SSL) Protocol
    Version 3.0", **RFC 6101** (Historic), IETF, 2011.
[13] T. Duong, J. Rizzo, "Here Come The ⊕ Ninjas" (BEAST), 2011.
[14] MITRE, "CVE-2011-3389" (SSL/TLS 1.0 CBC — BEAST), 2011.
[15] D. Plummer, "An Ethernet Address Resolution Protocol", **RFC 826**, IETF,
    1982.
[16] G. Bard, "A Challenging but Feasible Blockwise-Adaptive Chosen-Plaintext
    Attack on SSL", *SECRYPT*, 2006.
[17] T. Dierks, E. Rescorla, "The TLS Protocol Version 1.1", **RFC 4346**, 2006.
[18] P. Biondi *et al.*, *Scapy Documentation*, scapy.readthedocs.io.
[19] D. Adrian *et al.*, "Imperfect Forward Secrecy: How Diffie-Hellman Fails in
    Practice" (Logjam), *ACM CCS*, 2015.
[20] MITRE, "CVE-2015-4000 (Logjam)", *Common Vulnerabilities and Exposures*,
    2015.

---

## Appendix A — Flashcards (active recall)

> Question → answer format, ready to import into Anki/Obsidian-Spaced-Repetition.

1. **Q:** What does verifying a certificate signature *by hand* reveal compared to
   `openssl verify`?
   **A:** The concrete signature↔body link: ASN.1 walk, BIT STRING extraction,
   public RSA decryption, comparison to the TBSCertificate digest (C1).

2. **Q:** What are the three fundamental Scapy gestures?
   **A:** Sniff (`sniff`/BPF filter), dissect (`pkt[layer]`), craft & send
   (`IP()/UDP()/Raw()`, `sr1`) (C2).

3. **Q:** Why does cleartext HTTP offer no confidentiality against a MITM?
   **A:** Without transport encryption, ARP poisoning (RFC 826) is enough to read
   all traffic (C3).

4. **Q:** What are the three guarantees of a TLS channel, and which one does an
   unvalidated self-signed certificate void?
   **A:** Confidentiality, integrity, peer authentication; authentication falls
   (C4).

5. **Q:** What is the difference between the C5 key leak and the C6 one?
   **A:** C5 decrypts an *application* blob (RSA-OAEP) directly; C6 decrypts a
   **recorded** TLS session *after the fact* because RSA exchange offers no
   forward secrecy.

6. **Q:** Why does RSA exchange (C6) allow retroactive decryption, and what
   prevents it?
   **A:** The pre-master secret is encrypted under the server's long-term key; a
   later leak recomputes it. The **ECDHE** ephemeral destroys the secret after use
   → no leak reconstructs it (C6).

7. **Q:** How does Logjam (C7) differ from C6 even though DHE is *ephemeral*?
   **A:** The ephemeral exists but the DH group is downgraded to 512 bits; its
   discrete log is precomputable (amortized over the shared prime) → *imperfect*
   forward secrecy. Fix: DH ≥ 2048 bits / ECDHE, and no EXPORT (C7).

8. **Q:** Why is precomputation central to Logjam?
   **A:** The (high) discrete-log cost on a given prime is paid *once*, then
   reused against every server sharing that prime (C7).

9. **Q:** Which header, and which complementary mechanism, neutralize SSL
   stripping?
   **A:** `Strict-Transport-Security` (HSTS, RFC 6797) + listing on the *preload
   list* to cover the very first visit (C8).

10. **Q:** Which property of SSL 3.0's CBC padding does POODLE rely on, and what
    prevents it?
    **A:** The padding content is unspecified → an oracle exploitable byte by
    byte; `TLS_FALLBACK_SCSV` (RFC 7507) blocks the downgrade (C9).

11. **Q:** What makes the IV predictable in TLS 1.0 (BEAST), and what closes the
    flaw?
    **A:** A record's IV is the previous record's last ciphertext block; TLS 1.1
    mandates an explicit per-record IV, or apply 1/n-1 splitting (C10).

12. **Q:** Is Heartbleed a protocol or an implementation flaw?
    **A:** Implementation (OpenSSL): the Heartbeat payload length (RFC 6520) is
    unchecked → out-of-bounds read up to 64 KB (C11).

13. **Q:** Three distinct ways to lose the confidentiality of a key exchange —
    name them via C6, C7 and the common remedy.
    **A:** No ephemeral (RSA, C6); ephemeral too weak/downgraded (DH 512, Logjam
    C7); common remedy: robust ephemerals (ECDHE or DH ≥ 2048 bits).

## Appendix B — Acronym glossary

| Acronym | Expansion | Explanation |
|---------|-----------|-------------|
| **TLS** | *Transport Layer Security* | Transport-securing protocol, successor to SSL [5, 8]. |
| **SSL** | *Secure Sockets Layer* | TLS's ancestor; SSL 3.0 is obsolete (Historic, RFC 6101) [12]. |
| **HTTPS** | *HTTP Secure* | HTTP wrapped in TLS. |
| **MITM** | *Man-In-The-Middle* | Attacker interposed on the channel, reading/rewriting traffic. |
| **PKI** | *Public Key Infrastructure* | Infrastructure managing certificates and trust (RFC 5280) [4]. |
| **PFS** | *Perfect Forward Secrecy* | Leaking a long-term key does not compromise past sessions (C6, C7). |
| **CA** | *Certificate Authority* | Authority that signs and attests certificates. |
| **SAN** | *Subject Alternative Name* | Certificate field listing the covered identities (domains). |
| **CRL** | *Certificate Revocation List* | List of revoked certificates. |
| **ASN.1** | *Abstract Syntax Notation One* | Structure notation of X.509 certificates (walked in C1). |
| **TBS** | *To Be Signed (Certificate)* | The actually-signed body of the certificate (compared in C1). |
| **HSTS** | *HTTP Strict Transport Security* | Header forcing HTTPS on the client side (RFC 6797) [6]. |
| **CBC** | *Cipher Block Chaining* | Block mode; its padding/IV flaws underlie POODLE and BEAST. |
| **IV** | *Initialization Vector* | CBC seeding block; its predictability in TLS 1.0 underlies BEAST [13]. |
| **AEAD** | *Authenticated Encryption with Associated Data* | Authenticated encryption (AES-GCM) with no CBC oracle. |
| **SCSV** | *Signaling Cipher Suite Value* | Dummy suite signaling a fallback, basis of `TLS_FALLBACK_SCSV` (RFC 7507) [9]. |
| **RSA** | *Rivest–Shamir–Adleman* | Asymmetric cryptosystem; in RSA *key exchange*, no forward secrecy (C6). |
| **kRSA** | *(key exchange) RSA* | TLS suites where the pre-master secret is encrypted under the server's RSA key (C6). |
| **DH** | *Diffie-Hellman* | Key exchange based on the discrete logarithm; too small a group (512 bits) is breakable (C7). |
| **DHE** | *Diffie-Hellman Ephemeral* | Ephemeral variant (carries PFS if the group is robust); downgraded to EXPORT in Logjam (C7). |
| **ECDHE** | *Elliptic Curve Diffie-Hellman Ephemeral* | Ephemeral exchange over an elliptic curve, the forward-secrecy standard. |
| **EXPORT** | *EXPORT (suites)* | Old weakened suites (keys/groups ≤ 512 bits) imposed by US regulation; basis of Logjam/FREAK [19]. |
| **OAEP** | *Optimal Asymmetric Encryption Padding* | Safe padding for RSA encryption (used in C5). |
| **BPF** | *Berkeley Packet Filter* | Capture filtering language (Scapy `sniff`, `tcpdump`). |
| **BEAST** | *Browser Exploit Against SSL/TLS* | Chosen-plaintext attack on TLS 1.0/CBC (CVE-2011-3389) [13, 14]. |
| **CVE** | *Common Vulnerabilities and Exposures* | Public vulnerability identification system (MITRE). |
| **RFC** | *Request For Comments* | IETF normative document. |
| **ARP** | *Address Resolution Protocol* | IP↔MAC protocol; its hijacking (*spoofing*) positions the MITM (RFC 826) [15]. |
| **IaC** | *Infrastructure as Code* | Declarative, versioned infrastructure management [1]. |

---
*Environment strictly for teaching purposes*


<br>

---

# 🇫🇷 Version française

# TP « Sécurité HTTPS » — Laboratoire de challenges TLS

**Contexte** : travaux pratiques sur la sécurité du transport HTTPS, structurés en
onze challenges de type *capture-the-flag*. Deux challenges de **prise en main**
(OpenSSL, Scapy) outillent l'apprenant, un challenge d'**interception en clair**
(MITM HTTP) installe la posture d'attaquant réseau, puis huit challenges mettent
en défaut, de façon contrôlée, une propriété distincte de la sécurité TLS — afin
que l'apprenant reconstruise expérimentalement le lien entre *garantie théorique*
et *condition de mise en œuvre*.

> ⚠️ **Avertissement.** Ce laboratoire embarque des piles TLS volontairement
> vulnérables (échange RSA sans PFS, DHE export 512 bits, SSL 3.0, TLS 1.0/CBC,
> OpenSSL 1.0.1f). Il doit être exécuté exclusivement dans un réseau isolé,
> jamais routable vers un réseau de production ou vers Internet (cf. §8).

> 📘 Le **corrigé instructeur** (résolution *outils grand public* **puis**
> *Scapy* pour chaque challenge) est fourni séparément dans `SOLUTIONS.md`, avec
> les scripts Scapy de référence sous `solutions/scapy/`.

---

## 1. Objectifs pédagogiques

À l'issue du TP, l'apprenant doit être capable de :

1. **manipuler l'outillage de base** : fabriquer, inspecter et vérifier à la main
   un certificat X.509 avec OpenSSL (parcours ASN.1) ; renifler, disséquer,
   forger et émettre des paquets avec Scapy [18] ;
2. distinguer les trois garanties d'un canal TLS — **confidentialité**,
   **intégrité**, **authentification du pair** — et démontrer qu'elles sont
   *séparables* (un canal peut chiffrer sans authentifier ; un canal peut n'offrir
   aucune garantie s'il n'y a pas de TLS du tout) [5, 8] ;
3. relier chaque vulnérabilité à la couche fautive : identité (PKI), gestion des
   secrets, **forward secrecy** (absente ou *imparfaite*), négociation de
   protocole, ou implémentation ;
4. se placer en **homme-du-milieu** (empoisonnement ARP, RFC 826 [15]) et
   mobiliser l'outillage public (bettercap, mitmproxy, `openssl s_client`,
   Wireshark/tshark, `nmap --script ssl-*`, `testssl.sh`) ;
5. formuler pour chaque attaque la **contre-mesure normative** correspondante
   (validation RFC 5280, échanges éphémères ECDHE/PFS, groupes DH ≥ 2048 bits,
   HSTS RFC 6797, `TLS_FALLBACK_SCSV` RFC 7507, fractionnement 1/n-1 et IV
   explicite RFC 4346, mise à jour d'OpenSSL) [4, 6, 9, 17, 19].

## 2. Modèle de menace et architecture

Le modèle retenu est celui de l'**attaquant réseau actif** (Dolev–Yao) placé
entre un client-victime et un serveur : il peut lire, réécrire, rejouer et
injecter des paquets, mais ne dispose *a priori* d'aucun secret cryptographique.
Les challenges C6 et C7 enrichissent ce modèle : C6 ajoute la **compromission
différée** (enregistrer maintenant, obtenir la clé plus tard) ; C7 (Logjam) ajoute
la **rétrogradation active** d'un échange éphémère vers un groupe si faible que le
calcul du logarithme discret devient réalisable après un **précalcul amorti** sur
le nombre premier partagé [8, 19].

Principe de conception structurant : **le portail applicatif n'est jamais troué
au sens applicatif**. La vulnérabilité réside systématiquement dans la couche de
*transport* placée devant lui (terminaison TLS par nginx/apache/openssl), ou dans
son absence (MITM HTTP). Cette séparation isole la variable étudiée et évite de
confondre faille web (hors périmètre) et faille TLS (objet du TP).

```
          Réseau de laboratoire isolé (172.28.0.0/24)
  ┌───────────────┐        MITM        ┌────────────────────────────┐
  │ client-victime│◄─────attaquant────►│  cible Cx : front-end TLS  │
  │  (imprudent)  │                    │  VULNÉRABLE  →  portail     │
  └───────┬───────┘                    └──────────────┬─────────────┘
          │ armé par (IP dest.)                       │ proxy clair
          └───────────────  Portail Flask  ───────────┘
              (flux flag chiffré · start · verify)
```

Composants (cf. `docker-compose.yml`) :

| Rôle | Conteneur | Fonction |
|------|-----------|----------|
| Portail | `portal` | Sert le flag chiffré, arme le client-victime, vérifie les flags |
| Victime | `victim-client` | Émet le trafic imprudent à intercepter |
| Cibles | `c1`…`c11` | Front-ends vulnérables (ou balise Scapy), un par challenge |

Le portail refuse toute IP de destination hors de `LAB_CIDR` : il ne peut donc
pas être détourné en lanceur d'attaque générique (validation dans `app/app.py`).
Les warm-ups (C1 OpenSSL, C2 Scapy) sont des interactions *directes* avec la
cible et ne mobilisent pas le client-victime.

## 3. Cartographie challenge → couche mise en défaut

| # | Challenge | Couche / compétence | Garantie annulée | Réf. |
|---|-----------|---------------------|------------------|------|
| 1 | Prise en main OpenSSL | Outillage X.509 (ASN.1) | — (formation) | [4] |
| 2 | Prise en main Scapy | Outillage réseau (sniff/forge) | — (formation) | [15, 18] |
| 3 | MITM contre HTTP | Absence de transport chiffré | Confidentialité (totale) | [15] |
| 4 | Certificat auto-signé + MITM | Identité PKI | Authentification | [4] |
| 5 | Fuite de clé privée | Gestion des secrets (RSA-OAEP applicatif) | Confidentialité persistante | — |
| 6 | Absence de forward secrecy | Échange de clés RSA (pas d'éphémère) | Confidentialité *rétroactive* | [5, 8] |
| 7 | Logjam (DHE export) | Groupe DH 512 bits + downgrade | Confidentialité (*imperfect* FS) | [19, 20] |
| 8 | SSL stripping | Politique de transport | Confidentialité (via downgrade) | [6, 7] |
| 9 | POODLE (SSLv3/CBC) | Négociation + mode CBC | Confidentialité | [9, 10] |
| 10 | BEAST (TLS 1.0/CBC) | IV prévisible (CBC chaîné) | Confidentialité (chosen-plaintext) | [13, 14, 16] |
| 11 | Heartbleed | Implémentation (RFC 6520) | Confidentialité (mémoire) | [3, 11] |

> **C6 → C7 — la même leçon, deux degrés.** C6 : *aucun* éphémère (échange RSA) →
> la fuite de la clé long-terme déchiffre tout le passé. C7 : l'éphémère existe
> (DHE) mais il est **rétrogradé** vers un groupe de 512 bits dont le logarithme
> discret est précalculable — la forward secrecy est *présente mais imparfaite*
> (d'où le titre de l'article fondateur, « Imperfect Forward Secrecy » [19]). La
> parade commune : des éphémères **robustes** (ECDHE, ou DH ≥ 2048 bits).

## 4. Construction des images (Packer)

Deux voies, au choix de l'enseignant :

**(a) Packer → Docker** — image du portail construite par *provisioning* immuable
(`packer/portal.pkr.hcl`). Cette approche « image immuable » [1, 2] garantit la
reproductibilité bit-à-bit indépendamment d'un `docker build` local :

```sh
cd packer && packer init . && packer build -only='docker.*' .
```

**(b) Packer → QEMU** — cuisson d'une **VM autonome** embarquant tout le lab
(`packer/lab-vm.pkr.hcl`). Livrable idéal en salle : un unique `qcow2` remis à
chaque étudiant, sans dépendance réseau à l'exécution (isolement garanti) :

```sh
cd packer && packer init . && packer build -only='qemu.*' .
# → output-lab-vm/tls-lab.qcow2
```

> `-only` cible l'**adresse** du build (`<type>.<source>`, p. ex.
> `docker.docker.portal`) ; les motifs `'docker.*'` / `'qemu.*'` évitent d'avoir à
> l'écrire en toutes lettres.
>
> La VM requiert un `packer/http/user-data` (cloud-init) avec un hachage de mot
> de passe valide : générez-le via `mkpasswd -m sha-512` et remplacez le
> paramètre `passwd:` fourni en exemple.

## 5. Déploiement du laboratoire

Le TP se déploie de **trois façons**, selon le contexte :

| Mode | Outil | Topologie | Où |
|------|-------|-----------|-----|
| **Local** (poste unique) | Packer + Compose | tout sur une machine (ou une VM `qcow2`) | ci-dessous + `packer/` |
| **Salle de TP** (parc) | Ansible (+ Packer) | portail sur la prof, cibles+victime sur chaque poste | `ansible/` (`site.yml`) |
| **Centralisé anti-triche** | Ansible (+ Packer) | tout sur le serveur prof, une instance isolée/étudiant, accès SSH confiné | `ansible/` (`centralized.yml`) |

En **salle de TP** (mode 2), le portail — le site qui reçoit et vérifie les
flags — est centralisé sur la machine prof ; chaque poste n'héberge que les
cibles et le client-victime, qui proxifient vers ce portail (`portal → IP_prof`
via `extra_hosts`). La victime tourne en mode *standalone*. Déploiement :
`cd ansible && ansible-playbook site.yml`.

En **centralisé anti-triche** (mode 3), **tout** tourne sur le serveur prof, en
une **instance isolée par étudiant** (portail + cibles + victime + attaquant, sur
un réseau `/24` dédié et hermétique). L'étudiant n'a **aucun accès Docker/hôte** :
il se connecte par **SSH** (`ForceCommand`) dans son seul conteneur attaquant, et
les **flags C2–C11 sont uniques par étudiant** — impossible d'extraire un flag
d'une image ou de le partager. Déploiement : `cd ansible && ansible-playbook
centralized.yml` (voir `ansible/README.md`).

### Mode local

```sh
make up          # docker compose build && up -d
# Cibles : 8451(C1) · 8453(C3) · 8441(C4) · 8442(C5) · 8447(C6) · 8448(C7)
#          8006/8443(C8) · 8444(C9) · 8446(C10) · 8445(C11).
#          C2 = balise Scapy interne (UDP/8452).
```

### Option « debug » — proxy d'observation

Un override Compose insère un **proxy d'inspection** (mitmproxy/mitmweb) par
lequel transite **tout le trafic du client-victime**. La victime acceptant déjà
n'importe quel certificat, mitmproxy **déchiffre** les sessions TLS victime↔cible
et affiche en clair chaque échange (flux du flag, blob RSA-OAEP, clé fuitée,
cookies POODLE/BEAST/Logjam, page Heartbleed…) — pratique pour vérifier qu'un
challenge délivre bien son flag ou pour une démonstration.

```sh
make debug        # = docker compose -f docker-compose.yml -f docker-compose.debug.yml up -d
# → interface d'inspection : http://localhost:8081
make debug-down
```

> Ce mode **route la victime à travers le proxy** (victime → proxy → cible) : il
> sert au débogage/à la démonstration côté enseignant, **pas** aux sessions
> d'attaque des étudiants (il déplace le chemin que viserait l'ARP spoofing).
> Pour une capture sans interface, remplacer `mitmweb` par `mitmdump -w …` dans
> `docker-compose.debug.yml`.

Pour un isolement total, basculer `internal: true` sur le réseau `lab` dans
`docker-compose.yml`. Le poste d'attaque se joint au réseau `lab` (ou l'on
`docker compose exec` un conteneur outillé) : Scapy y voit la balise C2 et peut y
empoisonner l'ARP.

## 6. Déroulé détaillé par challenge

Chaque section suit le même canevas : *contexte → chaîne d'exploitation →
contre-mesure normative*. Les corrections complètes (outils publics **et** Scapy)
sont dans `SOLUTIONS.md`.

### C1 — Prise en main d'OpenSSL (10 pts)
- **But** : récupérer le certificat auto-signé de la cible (`openssl s_client`),
  l'inspecter (`openssl x509 -text`), puis **vérifier sa signature à la main**
  (parcours `asn1parse`, extraction du BIT STRING, `rsautl -verify`, comparaison
  au condensat du TBSCertificate). Le flag est embarqué dans le champ *OU* du
  certificat.
- **Enseignement** : dérouler manuellement ce que `openssl verify` automatise ;
  comprendre la structure ASN.1 et le lien signature ↔ corps (RFC 5280 [4]).

### C2 — Prise en main de Scapy (10 pts)
- **But** : renifler la balise UDP/8452 (`sniff(filter="udp port 8452")`), lire la
  consigne, **forger** le datagramme magique et l'**émettre** (`sr1`) ; la cible
  répond alors avec le flag.
- **Enseignement** : les trois gestes de Scapy — sniff, dissection en couches,
  forge/émission — socle des challenges MITM suivants [18].

### C3 — MITM contre HTTP en clair (20 pts)
- **Transport** : HTTP clair (port 8453), **aucun TLS**.
- **Exploitation** : empoisonnement ARP (`arp_spoof.py` ou bettercap) entre
  victime et cible, puis sniffing (`sniff_http_flag.py` / tcpdump) ; le flag
  transite en clair.
- **Enseignement** : sans chiffrement de transport, la confidentialité est nulle ;
  l'interception active (RFC 826 [15]) suffit.
- **Contre-mesure** : HTTPS obligatoire + redirection permanente + HSTS (cf. C8).

### C4 — Certificat auto-signé & MITM (15 pts)
- **Transport** : TLS 1.2, certificat auto-signé, *non validé par le client*.
- **Exploitation** : ARP-spoof du client-victime ; interception transparente
  (`bettercap`/`mitmproxy`) ; l'attaquant présente son propre certificat
  auto-signé, que la victime accepte (validation désactivée), et lit le flag.
- **Enseignement** : le chiffrement sans **authentification du pair** n'offre
  aucune protection contre un MITM ; la confiance repose sur la validation de la
  chaîne de certification [4].
- **Contre-mesure** : validation stricte RFC 5280 (chaîne, SAN, révocation) ;
  épinglage le cas échéant.

### C5 — Fuite de clé privée (20 pts)
- **Transport** : TLS sain, mais la clé privée RSA du portail est exposée sous
  `/.well-known/backup/server.key`. Le flag est publié chiffré **RSA-OAEP** par
  `/c/5/flag-feed`.
- **Exploitation** :
  ```sh
  curl -k https://CIBLE:8442/.well-known/backup/server.key -o server.key
  curl -k https://CIBLE:8442/c/5/flag-feed | jq -r .ciphertext_b64 | base64 -d > flag.bin
  openssl pkeyutl -decrypt -inkey server.key \
     -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in flag.bin
  ```
- **Enseignement** : la compromission d'une clé long-terme annule la
  confidentialité de tout ce qu'elle protège. Ici la protection est *applicative*
  (un blob) ; le C6 montre la même logique au niveau *transport*.
- **Contre-mesure** : cloisonnement des secrets, permissions restrictives,
  rotation, absence de secret dans une arborescence servie.

### C6 — Absence de forward secrecy / échange RSA (25 pts)
- **Transport** : TLS 1.2 négociant un **échange de clés RSA** (suites `kRSA` type
  `TLS_RSA_WITH_AES_128_CBC_SHA` ; aucun ECDHE/DHE). Le secret pré-maître est
  chiffré sous la clé publique RSA du serveur et transporté dans le
  ClientKeyExchange. La clé privée du serveur est exposée sous
  `/.well-known/backup/server.key`.
- **Exploitation** (déchiffrement *a posteriori*) :
  1. **enregistrer** le trafic TLS de la victime : `tcpdump -i eth0 -w cap.pcap
     'host CIBLE and port 8447'` (au besoin en position MITM, cf. `arp_spoof.py`) ;
  2. **faire fuiter** la clé : `curl -k
     https://CIBLE:8447/.well-known/backup/server.key -o server.key` ;
  3. **déchiffrer** hors ligne : Wireshark → *Preferences ▸ Protocols ▸ TLS ▸ RSA
     keys list* (ajouter `server.key`), ou
     `tshark -r cap.pcap -o "tls.keys_list:CIBLE,8447,http,server.key" -Y http`.
     Le flag apparaît en clair dans la réponse HTTP déchiffrée.
- **Enseignement** : sans éphémère, la clé long-terme suffit à recalculer *toutes*
  les sessions passées capturées. La **forward secrecy** (ECDHE) rompt ce lien :
  chaque session dérive d'un secret éphémère détruit après usage, qu'aucune fuite
  ultérieure de la clé long-terme ne peut reconstituer [5, 8].
- **Contre-mesure** : imposer des suites **ECDHE** (forward secrecy) ; en TLS 1.3
  l'échange RSA statique est purement et simplement supprimé.

### C7 — Logjam / DHE export (25 pts)
- **Transport** : TLS 1.2 acceptant des suites **DHE de qualité EXPORT** — groupe
  Diffie-Hellman de **512 bits** (`EXP-EDH-RSA-DES-CBC-SHA`). Aucune protection
  contre le *downgrade*. Le flag est porté par le cookie `SESSIONFLAG`.
- **Exploitation** :
  1. **détecter** : `testssl.sh --logjam CIBLE:8448`, `nmap --script
     ssl-dh-params -p 8448 CIBLE`, ou `openssl s_client -connect CIBLE:8448
     -cipher EXP` (une session à 512 bits s'établit) ;
  2. en position **MITM**, forcer la rétrogradation du ClientHello vers la suite
     DHE_EXPORT (le serveur répond avec son groupe de 512 bits) ;
  3. **casser** le logarithme discret du groupe de 512 bits — coûteux une fois,
     mais **amorti** car le même nombre premier est partagé par d'innombrables
     serveurs (précalcul), d'où récupération du secret éphémère puis déchiffrement
     de la session et lecture du cookie [19, 20].
- **Enseignement** : un échange *éphémère* n'assure la forward secrecy que si le
  groupe est **robuste**. Un groupe export (512 bits), ou même un groupe de 1024
  bits partagé, est à la portée d'un précalcul (Logjam) : la FS devient
  *imparfaite*. C'est le pendant « DH » du C6 « RSA ».
- **Contre-mesure** : désactiver toutes les suites EXPORT ; imposer des groupes DH
  **≥ 2048 bits** (ou uniques par serveur) ; préférer ECDHE. Côté client, refuser
  les groupes DHE < 1024 bits (correctif Logjam des navigateurs) [19].

### C8 — SSL stripping (20 pts)
- **Transport** : service joignable en clair (port 80), **aucun HSTS**, lien
  `http://` en dur.
- **Exploitation** : MITM + rétrogradation HTTPS→HTTP (`bettercap` caplet
  `hstshijack`, ou `sslstrip2`) ; le flag transite alors en clair et est capturé.
- **Enseignement** : l'attaque de Marlinspike [7] exploite l'*amorçage* en clair.
  La parade est de rendre HTTPS **obligatoire et mémorisé** côté client.
- **Contre-mesure** : `Strict-Transport-Security` (HSTS, RFC 6797) avec
  `includeSubDomains` et inscription sur la *preload list* [6].

### C9 — POODLE / SSL 3.0 (25 pts)
- **Transport** : SSL 3.0 accepté, suites **CBC**, `TLS_FALLBACK_SCSV` absent →
  repli forcé possible. Le flag est porté par le cookie `SESSIONFLAG`.
- **Exploitation** : forcer le repli SSLv3 (`openssl s_client -ssl3`) ; en
  position MITM, exploiter l'**oracle de padding CBC** de SSL 3.0 pour
  reconstituer le cookie octet par octet [9, 10].
- **Enseignement** : SSL 3.0 ne spécifie pas le contenu du bourrage CBC, rendant
  sa vérification exploitable en oracle. Un protocole obsolète reste dangereux
  tant qu'un downgrade est possible.
- **Contre-mesure** : désactiver SSL 3.0 ; imposer `TLS_FALLBACK_SCSV` (RFC 7507)
  contre les rétrogradations [9].

### C10 — BEAST / TLS 1.0 CBC (25 pts)
- **Transport** : TLS 1.0 exclusivement, suites **CBC**. En TLS 1.0, l'IV d'un
  enregistrement est le dernier bloc chiffré du précédent : il est **prévisible**.
  Le flag est porté par le cookie `SESSIONFLAG`.
- **Exploitation** : confirmer (`openssl s_client -tls1`, `testssl.sh`,
  `nmap --script ssl-enum-ciphers`) ; en position MITM (empoisonnement ARP,
  `arp_spoof.py`), monter l'attaque à **texte clair choisi adaptatif**
  (blockwise chosen-boundary) qui aligne la frontière de bloc et devine le cookie
  octet par octet [13, 14, 16].
- **Enseignement** : un IV prévisible transforme le chiffrement CBC en oracle de
  texte clair choisi. C'est une faiblesse de **conception protocolaire** (TLS
  1.0), distincte de l'oracle de *padding* de POODLE.
- **Contre-mesure** : bannir TLS 1.0 ; à défaut, **fractionnement 1/n-1** ou
  suites AEAD (AES-GCM). TLS 1.1+ referme structurellement BEAST par un IV
  explicite par enregistrement (RFC 4346 [17]).

### C11 — Heartbleed / OpenSSL 1.0.1f (20 pts)
- **Transport** : OpenSSL 1.0.1f, extension **Heartbeat** (RFC 6520) sans
  contrôle de la longueur annoncée. Le flag réside en mémoire du processus.
- **Exploitation** :
  ```sh
  nmap -p 8445 --script ssl-heartbleed CIBLE     # détection
  # puis PoC RFC 6520 : requête Heartbeat avec payload_length surdimensionné
  # → lecture hors-limites jusqu'à 64 Ko, où figure le flag.
  ```
- **Enseignement** : une seule longueur non vérifiée expose des blocs mémoire
  arbitraires (clés, cookies, données) — illustration canonique d'une
  vulnérabilité d'implémentation, distincte d'une faiblesse de protocole [3, 11].
- **Contre-mesure** : mise à jour OpenSSL ≥ 1.0.1g ; régénération des secrets
  potentiellement exposés.

## 7. Barème

| Challenge | Points | Compétence évaluée |
|-----------|:------:|--------------------|
| C1 Prise en main OpenSSL | 10 | Manipulation X.509 / ASN.1 |
| C2 Prise en main Scapy | 10 | Sniff / forge / envoi |
| C3 MITM HTTP | 20 | Interception active (ARP) |
| C4 Cert. auto-signé | 15 | Validation PKI |
| C5 Fuite de clé | 20 | Gestion des secrets (applicatif) |
| C6 Forward secrecy (échange RSA) | 25 | Déchiffrement a posteriori / PFS |
| C7 Logjam (DHE export) | 25 | Downgrade DH + log discret précalculé |
| C8 SSL stripping | 20 | Défense MITM / HSTS |
| C9 POODLE | 25 | Oracle CBC / obsolescence |
| C10 BEAST | 25 | IV prévisible / chosen-plaintext |
| C11 Heartbleed | 20 | Divulgation mémoire |
| **Total** | **215** | |

## 8. Précautions, éthique et isolement

1. **Isolement absolu** : réseau non routable ; `internal: true` recommandé.
2. **Périmètre** : le portail n'arme le client-victime que vers des IP privées
   du `LAB_CIDR` — aucune attaque hors laboratoire n'est possible depuis l'appli.
3. **Capacités réseau** : la cible Scapy (C2) et les postes d'attaque requièrent
   `NET_RAW`/`NET_ADMIN` ; ne les accorder qu'au sein du réseau isolé.
4. **Cadre légal** : environnement contrôlé, consentement pédagogique documenté ;
   les techniques d'interception ne sont licites que sur une infrastructure dont
   on a la maîtrise.
5. **Cycle de vie** : détruire les instances vulnérables après le TP
   (`make clean`) ; conserver des instantanés « propres ».
6. **Débriefing** : chaque challenge se conclut par l'énoncé de sa contre-mesure.

### Caveats de reproductibilité (protocoles obsolètes)

Les protocoles hérités sont progressivement retirés des piles récentes :

- **C6 (échange RSA)** : les suites `kRSA` sont dépréciées ; réautorisées via
  `@SECLEVEL=1` dans `ssl_ciphers`. Wireshark ne déchiffre le trafic avec la clé
  privée **que** pour l'échange RSA (impossible avec ECDHE) — c'est précisément le
  point pédagogique.
- **C7 (Logjam)** : les suites **EXPORT** ont été retirées d'OpenSSL ≥ 1.0.2g. La
  cible est donc bâtie sur `ubuntu:14.04` (OpenSSL 1.0.1f, qui les embarque
  encore). Le **cassage du log discret 512 bits** n'est pas exécuté en séance : on
  s'appuie sur un précalcul/PoC pour le groupe connu (c'est *toute* la logique de
  Logjam — le précalcul est amorti). L'exercice évaluable est la **détection** et
  la **démonstration du downgrade** ; le déchiffrement complet est fourni « clé en
  main » par l'encadrant.
- **C9 (SSLv3)** : image `httpd:2.4.29` épinglée.
- **C10 (TLS 1.0)** : réactivé via `targets/beast/openssl-lab.cnf` (`MinProtocol=
  TLSv1`, `@SECLEVEL=0`). Base héritée sinon.
- **C11 (Heartbleed)** : OpenSSL 1.0.1f compilé depuis l'archive officielle.

Ces cibles n'ont **pas** été construites/exécutées dans l'environnement de
préparation (réseau désactivé) : valider le `docker build` sur un hôte outillé
avant la séance.

## 9. Reproductibilité et anti-triche

Les flags sont chargés depuis l'environnement (`FLAG_C1`…`FLAG_C11`), propagés de
façon cohérente au portail **et** à la cible correspondante via `docker-compose`.
Pour générer une instance unique par promotion ou par étudiant, définir un `.env`
puis `docker compose up -d --build --force-recreate`. La vérification se fait à
divulgation nulle (comparaison à temps constant sur empreinte SHA-256, cf.
`challenges.py`).

## 10. Références

[1] K. Morris, *Infrastructure as Code*, 2ᵉ éd., O'Reilly, 2020.
[2] HashiCorp, *Packer Documentation — Immutable Machine Images*, docs.packer.io.
[3] R. Seggelmann, M. Tuexen, M. Williams, « Transport Layer Security (TLS) and
    Datagram TLS (DTLS) Heartbeat Extension », **RFC 6520**, IETF, 2012.
[4] D. Cooper *et al.*, « Internet X.509 Public Key Infrastructure Certificate
    and CRL Profile », **RFC 5280**, IETF, 2008.
[5] T. Dierks, E. Rescorla, « The TLS Protocol Version 1.2 », **RFC 5246**, 2008.
[6] J. Hodges, C. Jackson, A. Barth, « HTTP Strict Transport Security (HSTS) »,
    **RFC 6797**, IETF, 2012.
[7] M. Marlinspike, « New Tricks for Defeating SSL in Practice », *Black Hat DC*,
    2009.
[8] E. Rescorla, « The Transport Layer Security (TLS) Protocol Version 1.3 »,
    **RFC 8446**, IETF, 2018.
[9] B. Möller, A. Langley, « TLS Fallback Signaling Cipher Suite Value (SCSV) for
    Preventing Protocol Downgrade Attacks », **RFC 7507**, IETF, 2015.
[10] B. Möller, T. Duong, K. Kotowicz, « This POODLE Bites: Exploiting the SSL
    3.0 Fallback », Google, 2014. (CVE-2014-3566)
[11] MITRE, « CVE-2014-0160 (Heartbleed) », *Common Vulnerabilities and
    Exposures*, 2014.
[12] A. Freier, P. Karlton, P. Kocher, « The Secure Sockets Layer (SSL) Protocol
    Version 3.0 », **RFC 6101** (Historic), IETF, 2011.
[13] T. Duong, J. Rizzo, « Here Come The ⊕ Ninjas » (BEAST), 2011.
[14] MITRE, « CVE-2011-3389 » (SSL/TLS 1.0 CBC — BEAST), 2011.
[15] D. Plummer, « An Ethernet Address Resolution Protocol », **RFC 826**, IETF,
    1982.
[16] G. Bard, « A Challenging but Feasible Blockwise-Adaptive Chosen-Plaintext
    Attack on SSL », *SECRYPT*, 2006.
[17] T. Dierks, E. Rescorla, « The TLS Protocol Version 1.1 », **RFC 4346**, 2006.
[18] P. Biondi *et al.*, *Scapy Documentation*, scapy.readthedocs.io.
[19] D. Adrian *et al.*, « Imperfect Forward Secrecy: How Diffie-Hellman Fails in
    Practice » (Logjam), *ACM CCS*, 2015.
[20] MITRE, « CVE-2015-4000 (Logjam) », *Common Vulnerabilities and Exposures*,
    2015.

---

## Annexe A — Flashcards (révision active)

> Format question → réponse, prêt à importer dans Anki/Obsidian-Spaced-Repetition.

1. **Q :** Que révèle la vérification *manuelle* d'une signature de certificat
   par rapport à `openssl verify` ?
   **R :** Le lien concret signature↔corps : parcours ASN.1, extraction du BIT
   STRING, déchiffrement RSA public, comparaison au condensat du TBSCertificate
   (C1).

2. **Q :** Quels sont les trois gestes fondamentaux de Scapy ?
   **R :** Renifler (`sniff`/filtre BPF), disséquer (`pkt[couche]`), forger &
   émettre (`IP()/UDP()/Raw()`, `sr1`) (C2).

3. **Q :** Pourquoi un flux HTTP en clair n'offre-t-il aucune confidentialité en
   présence d'un MITM ?
   **R :** Sans chiffrement de transport, l'empoisonnement ARP (RFC 826) suffit à
   lire l'intégralité du trafic (C3).

4. **Q :** Quelles sont les trois garanties d'un canal TLS, et laquelle un
   certificat auto-signé non validé annule-t-il ?
   **R :** Confidentialité, intégrité, authentification du pair ; c'est
   l'authentification qui tombe (C4).

5. **Q :** Quelle est la différence entre la fuite de clé du C5 et celle du C6 ?
   **R :** C5 déchiffre un blob *applicatif* (RSA-OAEP) directement ; C6 déchiffre
   *a posteriori* une session TLS **enregistrée** parce que l'échange RSA n'offre
   pas de forward secrecy.

6. **Q :** Pourquoi l'échange RSA (C6) permet-il un déchiffrement rétroactif, et
   qu'est-ce qui l'empêche ?
   **R :** Le secret pré-maître est chiffré sous la clé long-terme du serveur ;
   sa fuite ultérieure le recalcule. L'éphémère **ECDHE** détruit le secret après
   usage → aucune fuite ne le reconstitue (C6).

7. **Q :** En quoi Logjam (C7) diffère-t-il du C6 alors que DHE est *éphémère* ?
   **R :** L'éphémère existe mais le groupe DH est rétrogradé à 512 bits ; son log
   discret est précalculable (amorti sur le premier partagé) → forward secrecy
   *imparfaite*. Parade : DH ≥ 2048 bits / ECDHE, et pas d'EXPORT (C7).

8. **Q :** Pourquoi le précalcul est-il central dans Logjam ?
   **R :** Le coût (élevé) du logarithme discret sur un premier donné est payé
   *une fois*, puis réutilisé contre tous les serveurs partageant ce premier (C7).

9. **Q :** Quel en-tête, et quel mécanisme complémentaire, neutralisent le SSL
   stripping ?
   **R :** `Strict-Transport-Security` (HSTS, RFC 6797) + inscription sur la
   *preload list* pour couvrir la toute première visite (C8).

10. **Q :** Sur quelle propriété du bourrage CBC de SSL 3.0 repose POODLE, et
    qu'est-ce qui l'empêche ?
    **R :** Le contenu du padding n'est pas spécifié → oracle exploitable octet
    par octet ; `TLS_FALLBACK_SCSV` (RFC 7507) bloque le downgrade (C9).

11. **Q :** Qu'est-ce qui rend l'IV prévisible en TLS 1.0 (BEAST), et qu'est-ce
    qui referme la faille ?
    **R :** L'IV d'un enregistrement est le dernier bloc chiffré du précédent ;
    TLS 1.1 impose un IV explicite par enregistrement, ou fractionnement 1/n-1
    (C10).

12. **Q :** Heartbleed est-elle une faille de protocole ou d'implémentation ?
    **R :** D'implémentation (OpenSSL) : la longueur du payload Heartbeat (RFC
    6520) n'est pas contrôlée → lecture hors-limites jusqu'à 64 Ko (C11).

13. **Q :** Trois façons distinctes de perdre la confidentialité d'un échange de
    clés — nommez-les via C6, C7 et le remède commun.
    **R :** Pas d'éphémère (RSA, C6) ; éphémère trop faible/rétrogradé (DH 512,
    Logjam C7) ; remède commun : éphémères robustes (ECDHE ou DH ≥ 2048 bits).

## Annexe B — Glossaire des acronymes

| Acronyme | Développé | Explication |
|----------|-----------|-------------|
| **TLS** | *Transport Layer Security* | Protocole de sécurisation du transport, successeur de SSL [5, 8]. |
| **SSL** | *Secure Sockets Layer* | Ancêtre de TLS ; SSL 3.0 est obsolète (Historic, RFC 6101) [12]. |
| **HTTPS** | *HTTP Secure* | HTTP encapsulé dans TLS. |
| **MITM** | *Man-In-The-Middle* | Attaquant interposé sur le canal, lisant/réécrivant le trafic. |
| **PKI** | *Public Key Infrastructure* | Infrastructure de gestion des certificats et de la confiance (RFC 5280) [4]. |
| **PFS** | *Perfect Forward Secrecy* | La fuite d'une clé long-terme ne compromet pas les sessions passées (C6, C7). |
| **CA** | *Certificate Authority* | Autorité qui signe et atteste les certificats. |
| **SAN** | *Subject Alternative Name* | Champ du certificat listant les identités (domaines) couvertes. |
| **CRL** | *Certificate Revocation List* | Liste des certificats révoqués. |
| **ASN.1** | *Abstract Syntax Notation One* | Notation de structure des certificats X.509 (parcourue au C1). |
| **TBS** | *To Be Signed (Certificate)* | Corps du certificat effectivement signé (comparé au C1). |
| **HSTS** | *HTTP Strict Transport Security* | En-tête forçant l'usage de HTTPS côté client (RFC 6797) [6]. |
| **CBC** | *Cipher Block Chaining* | Mode par blocs ; ses défauts de padding/IV fondent POODLE et BEAST. |
| **IV** | *Initialization Vector* | Bloc d'amorçage CBC ; sa prévisibilité en TLS 1.0 fonde BEAST [13]. |
| **AEAD** | *Authenticated Encryption with Associated Data* | Chiffrement authentifié (AES-GCM) sans oracle CBC. |
| **SCSV** | *Signaling Cipher Suite Value* | Suite factice signalant un repli, base de `TLS_FALLBACK_SCSV` (RFC 7507) [9]. |
| **RSA** | *Rivest–Shamir–Adleman* | Cryptosystème asymétrique ; en *échange de clés* RSA, pas de forward secrecy (C6). |
| **kRSA** | *(key exchange) RSA* | Suites TLS où le secret pré-maître est chiffré sous la clé RSA du serveur (C6). |
| **DH** | *Diffie-Hellman* | Échange de clés fondé sur le logarithme discret ; un groupe trop petit (512 bits) est cassable (C7). |
| **DHE** | *Diffie-Hellman Ephemeral* | Variante éphémère (porteuse de PFS si le groupe est robuste) ; rétrogradée en EXPORT dans Logjam (C7). |
| **ECDHE** | *Elliptic Curve Diffie-Hellman Ephemeral* | Échange éphémère sur courbe elliptique, standard de forward secrecy. |
| **EXPORT** | *(suites) EXPORT* | Anciennes suites bridées (clés/groupes ≤ 512 bits) imposées par la réglementation US ; base de Logjam/FREAK [19]. |
| **OAEP** | *Optimal Asymmetric Encryption Padding* | Bourrage sûr pour le chiffrement RSA (utilisé au C5). |
| **BPF** | *Berkeley Packet Filter* | Langage de filtrage de capture (Scapy `sniff`, `tcpdump`). |
| **BEAST** | *Browser Exploit Against SSL/TLS* | Attaque chosen-plaintext sur TLS 1.0/CBC (CVE-2011-3389) [13, 14]. |
| **CVE** | *Common Vulnerabilities and Exposures* | Système d'identification public des vulnérabilités (MITRE). |
| **RFC** | *Request For Comments* | Document normatif de l'IETF. |
| **ARP** | *Address Resolution Protocol* | Protocole IP↔MAC ; son détournement (*spoofing*) positionne le MITM (RFC 826) [15]. |
| **IaC** | *Infrastructure as Code* | Gestion déclarative et versionnée de l'infrastructure [1]. |

---
*Environnement à visée strictement pédagogique*
