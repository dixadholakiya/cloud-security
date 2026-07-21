# Network Security — Advanced Practicals (Cisco Packet Tracer Edition)

> **Read this first:** Packet Tracer simulates a *subset* of real Cisco IOS behavior. Every section below is labeled:
> - 🟢 **Fully simulatable** — build it and watch it actually happen in PT
> - 🟡 **Partially simulatable** — PT lets you configure it and see some effect, but not the full real-world behavior
> - 🔴 **Concept/reference only** — PT has no support for this; use the config as reference material to type on real hardware later (DevNet Sandbox / CML / your work Cisco gear)

---

## PART 1 — INTRODUCTION TO NETWORK SECURITY

All of Part 1 is theory + observation using a basic topology, so everything here is 🟢 fully doable in Packet Tracer.

### Base topology to build first
```
PC1 --- Switch1 --- Switch2 --- PC2
              |
           Server1 (DHCP/DNS/AAA)
```
Devices needed: 2 PCs, 2 switches (2960 or similar), 1 Server. All standard PT devices.

### 1.1–1.2 Introduction & The Need for Security
Configure basic IP addressing on PC1/PC2, ping across, then check `show mac address-table` and `show vlan brief` on both switches to establish a baseline understanding of what "normal" looks like before you break things later.

### 1.3 Security Approaches
Build 2 VLANs (VLAN 10 = HR, VLAN 20 = Finance) across both switches, and place PC1 in VLAN 10, PC2 in VLAN 20. Add an ACL on the switch's SVI (if using a Layer 3 switch or router-on-a-stick) denying inter-VLAN traffic except explicitly permitted flows — this demonstrates the access-control/zero-trust approach.

### 1.4 Principles of Security
```
line vty 0 4
 transport input ssh
 login local
!
username netadmin privilege 15 secret Str0ngP@ss
service password-encryption
```
Confirm Telnet is refused and only SSH works (Packet Tracer fully supports this).

### 1.5 Types of Security Attacks
Use this base topology to categorize what you'll build later: passive (ARP table poisoning demo), active (DHCP rogue server), reconnaissance (`show cdp neighbors` from an unauthorized port), DoS (STP/broadcast storm).

### 1.6–1.8 Security Services / Mechanisms / Model
🟡 Partially simulatable — Packet Tracer supports basic AAA syntax against a local database or a simulated RADIUS server object, but full EAP negotiation detail is limited:
```
aaa new-model
aaa authentication login default local
username student secret Cisco123
```

---

## PART 2 — LAN SECURITY MECHANISMS AND ATTACKS

### 2.1 VLAN Hopping — 🟡 Partially simulatable
PT can't run a real DTP-spoofing tool, but you can **demonstrate the vulnerability and the fix** by configuring the switchport modes yourself:

**Vulnerable config (simulate the mistake):**
```
interface fa0/1
 switchport mode dynamic desirable
```
Explain: in real life, an attacker's NIC negotiating DTP would exploit this. In PT, show the concept by manually setting a port to trunk and demonstrating a PC connected to it can see multiple VLANs' broadcast traffic (use Simulation Mode to trace packets).

**Fix:**
```
interface fa0/1
 switchport mode access
 switchport nonegotiate
 switchport access vlan 10
```
Verify: `show interfaces trunk`, and in Simulation Mode confirm no trunk frames reach that port.

### 2.2 Tag Stack Attack (Q-in-Q) — 🔴 Concept/reference only
Packet Tracer doesn't support 802.1ad/QinQ tunneling. Present the config from the full guide as reference material and explain the concept verbally/on slides instead of demonstrating live.

### 2.3 Broadcast Floods — 🟢 Fully simulatable
This one works well in PT:
1. Connect Switch1 and Switch2 with **two** cables between them (no STP... actually PT runs STP by default, so to force a storm you'll temporarily disable it for the demo):
```
spanning-tree vlan 1 disable
```
2. Send a broadcast (e.g., a large ping or ARP request) and watch Simulation Mode — you'll see the frame loop infinitely between the switches, visibly demonstrating a broadcast storm.
3. Re-enable STP (`spanning-tree vlan 1`) and show the loop resolves, then apply storm-control:
```
interface range fa0/1 - 2
 storm-control broadcast level 20.00 10.00
```
Note: PT's storm-control command is accepted syntactically but its enforcement/logging is limited — treat the STP-disable/re-enable loop demo as the main teaching moment here.

### 2.4 ARP Spoofing — 🟡 Partially simulatable
No real spoofing tool exists in PT, but you can **manually demonstrate the effect**:
1. On PC2, manually add a static (wrong) ARP entry pointing PC1's IP to PC2's own MAC, using PC2's Desktop > Command Prompt: `arp -s <PC1_IP> <wrong_MAC>`
2. Show that traffic from PC2 to PC1 now goes to the wrong destination (Simulation Mode, trace the packet).
3. This illustrates the *effect* of ARP poisoning even without a real attack tool.
4. Reference the real defense (DHCP snooping + DAI) as config-only, since PT's DAI support is minimal/inconsistent:
```
ip dhcp snooping
ip dhcp snooping vlan 10
ip arp inspection vlan 10
```

### 2.5 DHCP DoS (Starvation) — 🔴 Concept/reference only
PT has no way to simulate a scripted DHCP starvation flood. Show the defensive config as reference:
```
ip dhcp snooping
interface fa0/1
 ip dhcp snooping limit rate 10
```

### 2.6 DHCP and DNS Hijacking — 🟢 Fully simulatable (the best one for PT!)
This is Packet Tracer's strongest demo:
1. Add a **second server** to the topology, connected to an access port, configured as a second DHCP server handing out a different (wrong) default gateway/DNS.
2. Disconnect/reconnect a PC (or `ipconfig /release` then `/renew` on its Desktop) — show it sometimes picks up the rogue server's bad gateway.
3. This visibly demonstrates real DHCP hijacking risk.
4. Apply the fix: on the switch port facing the legitimate server only:
```
ip dhcp snooping
ip dhcp snooping vlan 10
interface fa0/2
 ip dhcp snooping trust
```
Mark the rogue server's port as untrusted (default) and show (conceptually — PT's enforcement here is inconsistent across versions) that it should be blocked from issuing OFFERs.

### 2.7 Spanning Tree Attacks — 🟢 Fully simulatable
Great one for PT:
1. Build a 3-switch loop topology (triangle) and let STP elect a root bridge — check with `show spanning-tree`.
2. Simulate a "rogue" root bridge takeover by lowering priority on Switch3 (the one representing your rogue device):
```
spanning-tree vlan 1 priority 0
```
3. Show the topology recompute and Switch3 become root — visibly demonstrate the disruption (a real attack would use BPDU injection; here you're simulating the *result*).
4. Apply Root Guard on the legitimate ports and BPDU Guard on access ports:
```
interface fa0/1
 spanning-tree guard root
interface range fa0/3 - 24
 spanning-tree portfast
 spanning-tree bpduguard enable
```
5. Repeat step 2 — legitimate ports now block the rogue priority change from taking effect / show `err-disabled` state on access ports if a BPDU arrives there.

### 2.8 Control Plane Policing (CoPP) — 🔴 Concept/reference only
Not supported in Packet Tracer at all. Present the config from the full guide purely as reference/theory material.

### 2.9 Link Layer Security (802.1X / Port Security) — 🟡 Partially simulatable
Port security is 🟢 fully supported:
```
interface fa0/1
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky
```
Test by connecting a 3rd PC to the same port via a hub/extra switch and confirm the violation triggers (`show port-security interface fa0/1`).

802.1X itself is 🟡 limited — PT accepts basic `dot1x` syntax but real EAP negotiation with a RADIUS server is not fully functional; treat as reference.

### 2.10 Port Guard / BPDU Guard — 🟢 Fully simulatable
Combine into one access-port template and test as in §2.7 step 5 above.

### 2.11 802.1AE (MACsec) — 🔴 Concept/reference only
No support in Packet Tracer whatsoever. Present as slide/reference material only.

### 2.12 NetFlow — 🔴 Concept/reference only
Not supported. Reference material only — consider showing a screenshot/demo video of a real NetFlow collector (e.g., ntopng) instead.

### 2.13 RMON — 🔴 Concept/reference only
Not supported. Reference material only.

---

## Summary: What You Can Actually Demonstrate Live in Packet Tracer

| Fully Live (🟢) | Partial (🟡) | Reference Only (🔴) |
|---|---|---|
| Broadcast floods via STP-disable loop | VLAN hopping (manual, not real DTP exploit) | Tag stack / Q-in-Q attack |
| DHCP/DNS hijacking via rogue server | ARP spoofing (manual static ARP, not real tool) | DHCP starvation (scripted flood) |
| STP root-bridge takeover + Root/BPDU Guard | 802.1X / AAA | Control Plane Policing |
| Port security violations | | 802.1AE MACsec |
| | | NetFlow |
| | | RMON |

**Recommendation:** For your 2-hour session, lead with the three 🟢 fully-live demos (broadcast storm, DHCP/DNS hijacking, STP takeover + guard) since they'll actually visibly work and impress a training audience — then walk through the 🔴 reference-only configs as "here's what you'd type on real hardware" slides, pointing to the full GNS3/DevNet-based guide for when real image access is sorted out.
