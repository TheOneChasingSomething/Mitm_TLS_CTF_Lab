# Student guide — "HTTPS Security" lab (Standalone Mode)

> How to get started, how each challenge is played, and the commands you need to know in **standalone VM mode**. This guide does **not** contain the flags or full exploit chains — it gives you the method and the tools. Everything runs inside an **isolated Docker network** inside the VM; nothing here is legal or safe to run against external systems.

---

## 1. The lab in one picture

### VM Overview & Host Connection
* **Target OS & Build Method:** The standalone environment runs on a Debian/Linux VM provisioned automatically via **Packer (QEMU builder)** and configured using **Ansible** playbooks. The resulting `.qcow2` image contains all necessary Docker images, dependencies, and project files pre-deployed under `/opt/tls-lab`.
* **Hypervisor Network & Connection:** The VM runs in QEMU NAT mode. SSH access for maintenance/management is forwarded from the host on port 2222. The web portal is forwarded to port 5000 (`http://localhost:5000`).
* **SSH Access to the VM:** To open a terminal session on the VM host (as user `ansible`), run from your host machine:
  ```sh
  ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ansible@127.0.0.1

| Role | Address | Notes |
| --- | --- | --- |
| **You (attacker container)** | `172.28.0.12` | Shell accessed via `docker compose exec` |
| **Portal** (scoreboard/arming) | `172.28.0.10:5000` | Web UI — read objectives, arm, submit flags |
| **Victim client** | `172.28.0.11` | Replays traffic on demand; accepts *any* cert |
| **C0 recon** | *hidden — scan to find* | **Start here:** map the lab with `nmap` |
| C1 openssl-warmup | *scan to find (C0)* | TLS — inspect a certificate |
| C2 scapy-warmup | *scan to find (C0)* | UDP beacon — sniff & forge |
| C3 mitm-http | *scan to find (C0)* | Cleartext HTTP |
| C4 self-signed | *scan to find (C0)* | TLS, unvalidated identity |
| C5 private-key-leak | *scan to find (C0)* | TLS, key exposed under `/.well-known/` |
| C6 pfs-rsa | *scan to find (C0)* | TLS, RSA key exchange (no forward secrecy) |
| C7 logjam | *scan to find (C0)* | TLS, export DHE (weak 512-bit group) |
| C8 ssl-strip | *scan to find (C0)* | TLS with no HSTS |
| C9 poodle | *scan to find (C0)* | SSL 3.0, CBC |
| C10 beast | *scan to find (C0)* | TLS 1.0, CBC |
| C11 heartbleed | *scan to find (C0)* | TLS, OpenSSL 1.0.1f |

The targets' addresses are **not listed here on purpose** — finding them is challenge **C0**. Flags always look like `FLAG{...}`.

---

## 2. Accessing your tools and the portal

### Step 1: Open an attacker shell
From the project directory on the VM host (\`/opt/tls-lab\`), enter the attacker container:
```sh
cd /opt/tls-lab; docker exec -it tls-lab-attacker-1 bash
```

*(All commands in Sections 4 to 6 must be executed inside this container)*.

### Step 2: Open the portal

- **From your host browser:**
	Plaintext
	```
	http://localhost:5000
	```
- **From inside the attacker container (CLI check):**
	Bash
	```
	curl [http://172.28.0.10:5000](http://172.28.0.10:5000)
	```

---



## 3. Two kinds of challenge

**(A) Inspect / warm-up — C1 and C2.** No victim, no interception, nothing to arm. You connect directly to the target.

**(B) On-path / man-in-the-middle — C3 through C11.**

1. **Arm** the victim from the portal ("start challenge"). Enter the **TARGET IP** (where the victim should connect), **not** the victim's IP.
2. **Position yourself on the path** between victim (`172.28.0.11`) and target using **ARP spoofing**, then capture/tamper.

---

## 4. The MITM workflow (challenges C3–C11)

Inside the `attacker` container, interface is always **`eth0`**.

### Step 1 — Become a router

ip_forward should be 1
```sh
cat /proc/sys/net/ipv4/ip_forward
1
```

### Step 2 — Poison ARP caches

Poison both victim (`172.28.0.11`) and target so traffic routes through `eth0`:

```sh
# Run in background (&) or open two shell sessions:
arpspoof -i eth0 -t 172.28.0.11 <target-ip> &
arpspoof -i eth0 -t <target-ip> 172.28.0.11 &

```

### Step 3 — Capture and Arm

Start capture on `eth0`:

```sh
tcpdump -i eth0 -w cap.pcap "host 172.28.0.11 and host <target-ip>"

```

Now click **Arm** in the Portal. Stop `tcpdump` (Ctrl+C) and analyze `cap.pcap` with `tshark` or Wireshark.

---

## 5. Toolbox — commands reference

### OpenSSL — inspect certificates & TLS

```sh
# Connect and pull full cert chain
openssl s_client -connect <target-ip>:<port> -servername bank.tp.lan -showcerts

# Decode PEM cert
openssl x509 -in cert.pem -noout -text

# Decrypt RSA-OAEP blob (C5)
openssl pkeyutl -decrypt -inkey key.pem -in blob.bin -out flag.txt -pkeyopt rsa_padding_mode:oaep

```

### Traffic Analysis & Fingerprinting

```sh
# Capture full TCP stream
tcpdump -i eth0 -n -s 0 -w cap.pcap "tcp port <port>"

# Read capture file with display filters
tshark -r cap.pcap -Y "http or tls"

# Audit TLS ciphers & vulnerabilities
nmap --script ssl-enum-ciphers,ssl-heartbleed,ssl-dh-params -p <port> <target-ip>

```

### Scapy (Python interactive)

```python
# In interactive scapy:
sniff(iface="eth0", filter="udp port <port>", count=1, timeout=15)
pkt = IP(dst="<target-ip>")/UDP(dport=<port>)/Raw(load=b"GIVE-FLAG")
sr1(pkt, timeout=5)

```

Or in a python script using this example :
```python
#!/usr/bin/env python3
from scapy.all import IP, ICMP, TCP, sr1, sr

# 1. Envoi d'un Ping ICMP (Layer 3) vers une cible du lab
target_ip = "172.28.0.1" # Exemple : Passerelle ou autre conteneur

print(f"[*] Envoi d'un paquet ICMP Echo Request vers {target_ip}...")
packet = IP(dst=target_ip)/ICMP()

# sr1() envoie le paquet et attend la PREMIÈRE réponse
reply = sr1(packet, timeout=2, verbose=False)

if reply:
    print(f"[+] Hôte actif ! Réponse reçue de {reply.src}")
    reply.show() # Affiche le détail des couches du paquet reçu
else:
    print("[-] Aucune réponse (timeout).")

# 2. Exécution d'un Handshake TCP syn (SYN Scan sur le port 80)
print("\n[*] Test du port 80 (TCP SYN)...")
syn_pkt = IP(dst=target_ip)/TCP(dport=80, flags="S")
syn_ack = sr1(syn_pkt, timeout=2, verbose=False)

if syn_ack and syn_ack.haslayer(TCP):
    if syn_ack[TCP].flags == 0x12: # SYN-ACK (0x12)
        print(f"[+] Le port 80 est OUVERT sur {target_ip}")
    elif syn_ack[TCP].flags == 0x14: # RST-ACK (0x14)
        print(f"[-] Le port 80 est FERMÉ sur {target_ip}")
```


---

## 6. Getting started, challenge by challenge

* **C0 — recon (start here):**
```sh
nmap -sn 172.28.0.0/24
nmap -p- -sV <target-ip>
nmap -p <port> --script http-title <target-ip>

```


* **C1 — openssl-warmup:** No arming. Inspect server cert: `echo | openssl s_client -connect <target-ip>:<port> | openssl x509 -noout -text`.
* **C2 — scapy-warmup:** No arming. Sniff UDP beacon on `eth0`, forge payload, send response.
* **C3 — mitm-http:** Arm target, ARP spoof (`eth0`), capture cleartext HTTP.
* **C4 — self-signed:** Arm target, ARP spoof, terminate TLS using `mitmproxy` / `bettercap`.
* **C5 — private-key-leak:** Download key via `curl -k https://<target-ip>:<port>/.well-known/...` and decrypt RSA-OAEP blob.
* **C6 — pfs-rsa:** Capture TLS traffic, retrieve leaked private key, load into Wireshark (*TLS ▸ RSA keys list*) to decrypt historical session.
* **C7 — logjam:** Detect weak 512-bit export DHE, force downgrade on-path.
* **C8 — ssl-strip:** Strip HTTPS down to HTTP using `bettercap` or `sslstrip`.
* **C9 — poodle (SSL 3.0):** Force SSLv3, execute padding oracle attack on CBC session cookie.
* **C10 — beast (TLS 1.0):** Exploit predictable IVs in TLS 1.0 CBC.
* **C11 — heartbleed:** Probe with `ssl-heartbleed`, dump up to 64KB memory.

---

## 7\. Recommended Workflows & Usage Examples

### Workflow 1: Standard Challenge Resolution (MITM Attack)

Here is the step-by-step procedure to resolve an on-path challenge (e.g., C3 or C6):

1. **Open Portal:** Navigate to `http://localhost:5000` on your host machine to read the challenge objective.
2. **Open Attacker Shell:** SSH into the VM host and enter the attacker container:
	Bash
	```
	ssh -p 2222 ansible@127.0.0.1
	cd /opt/tls-lab
	docker exec -it tls-lab-attacker-1 bash
	```
3. **Setup MITM:** Inside the container, enable routing and start poisoning:
	Bash
	```
	arpspoof -i eth0 -t 172.28.0.11 <target-ip> &
	arpspoof -i eth0 -t <target-ip> 172.28.0.11 &
	```
4. **Start Capture:** Output directly to `/captures` so it is shared with the VM:
	Bash
	```
	tcpdump -i eth0 -w /captures/challenge.pcap "host 172.28.0.11"
	```

	Timestamp and a file can be used to improved logging
	```sh
	tcpdump -i eth0 -n 2>&1 |  awk '{ print strftime("[%Y-%m-%d %H:%M:%S] [tcpdump]"), $0; fflush() }' >> lab.log &
	```

	```sh

	arpspoof -i eth0 -t 172.28.0.11 172.28.0.23 2>&1 | awk '{ print strftime("[%Y-%m-%d %H:%M:%S] [arpspoof-victim]"), $0; fflush() }' >> lab.log &

	arpspoof -i eth0 -t 172.28.0.23 172.28.0.11 2>&1 | awk '{ print strftime("[%Y-%m-%d %H:%M:%S] [arpspoof-server]"), $0; fflush() }' >> lab.log &
	```

5. **Arm Challenge:** Click **Arm** in the web portal (`http://localhost:5000`) with the `<target-ip>`.
6. **Retrieve & Analyze PCAP:**
	- Stop `tcpdump` (Ctrl+C).
		- From your **host machine**, copy the capture to analyze it in Wireshark locally:
		Bash
		```
		scp -P 2222 ansible@127.0.0.1:/opt/tls-lab/captures/challenge.pcap ./
		```
7. **Submit Flag:** Copy the `FLAG{...}` found and submit it on the portal.

### Workflow 2: Exporting / Importing Files Between Host, VM, and Attacker

The directory `/opt/tls-lab/captures` on the VM is mapped to `/captures` inside the `attacker` container.

- **Attacker Container ➔ Host Machine:** Save any file to `/captures/my_file` inside the container, then pull it from your host:
	Bash
	```
	scp -P 2222 ansible@127.0.0.1:/opt/tls-lab/captures/my_file ./
	```
- **Host Machine ➔ Attacker Container:** Push a script or custom payload from your host to the VM:
	Bash
	```
	scp -P 2222 ./exploit.py ansible@127.0.0.1:/opt/tls-lab/captures/
	```
	It will immediately be available at `/captures/exploit.py` inside the `attacker` container shell.

## 8. Troubleshooting (Standalone)

* **`docker compose exec` fails:** Vérifie que les conteneurs tournent via `docker compose ps` depuis `/opt/tls-lab`.
* **No traffic captured:** Check `ipv4.ip_forward` inside container (must be `1`), ensure `arpspoof` uses `eth0`.
* **`s_client` hangs:** Pipe `echo |` or add `</dev/null`.

```
docker exec -u 0  tls-lab-victim-client-1 tcpdump -i eth0 -s0 -X

docker run --rm -it --net=container:tls-lab-victim-client-1 nicolaka/netshoot tcpdump -i eth0 -n

docker exec -u 0 -it tls-lab-victim-client-1 ip neigh flush all

sudo ip neigh replace <IP> lladdr <MAC> dev eth0 nud permanent

docker logs -f victim
```