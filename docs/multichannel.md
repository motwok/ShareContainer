# SMB Multichannel

A single TCP connection uses one link. SMB Multichannel lets one client open several connections to the
server and spread its requests over them; Windows sends each request on the connection with the fewest
outstanding requests. With several links the throughput adds up.

## Two ways

**Several network cards, no teaming.** Each card has its own address on both sides. List every server
interface under `network.interfaces`; the client connects over each of its cards. No hashing is involved,
so the links are used evenly.

**NIC team or bond.** Client and server bundle their cards (LACP). With `smb.multichannel: true`
ShareContainer announces the interface as RSS capable, and Windows opens several connections to the same
server address. Team, switch and bond place each connection on one link by a hash over addresses and
ports, so the distribution depends on:

- **Hashing over layer 3+4** everywhere: Windows team `TransportPorts` or `Dynamic`, Linux bond
  `xmit_hash_policy layer3+4` or `encap3+4`, and the switch.
- **Enough connections.** Few connections often land unevenly; set 16 per interface on the client:

  ```powershell
  Set-SmbClientConfiguration -ConnectionCountPerRssNetworkInterface 16 -Force
  ```

  Windows keeps an existing session; disconnect the share (or restart the container) to get the new
  count.
- **Ethernet flow control (802.3x pause) off** on the team and bond ports, or on the switch. With flow
  control an overloaded switch port pauses whole links, including connections that would have room,
  and throughput stays at about two thirds of the bundle without any packet loss. Windows (per team
  member, elevated):

  ```powershell
  Set-NetAdapterAdvancedProperty -Name 'Ethernet 1' -RegistryKeyword '*FlowControl' -RegistryValue 0
  ```

  Linux (per bond member; make it persistent in your network configuration):

  ```sh
  ethtool -A eno1 autoneg off rx off tx off
  ```

## Example measurement

4 x 1 GbE team (Windows 11, LBFO, LACP) to a 4 x 1 GbE bond (Linux, `encap3+4`), host network, 10 GB in 8
files with `robocopy /J /MT:8`:

| Setting | Write | Read |
|---|---|---|
| flow control on, 16 connections | 2.2-2.6 Gbit/s | 2.6-3.3 Gbit/s |
| flow control off, 4 connections | 2.7 Gbit/s | 1.7-1.9 Gbit/s |
| flow control off, 8 connections | 3.4-3.6 Gbit/s | 2.8-3.5 Gbit/s |
| flow control off, 16 connections | 3.6-3.75 Gbit/s | 3.3-3.7 Gbit/s |

## Check on Windows

During a large copy, in an elevated PowerShell:

```powershell
Get-SmbMultichannelConnection
Get-SmbClientNetworkInterface
```

`ServerRSSCapable` must be `True` and several connections must be listed.
