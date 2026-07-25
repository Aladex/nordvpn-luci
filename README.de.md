# NordVPN WireGuard für OpenWrt

[English](README.md) · [Русский](README.ru.md) · **Deutsch**

Richtet den WireGuard-Dienst (NordLynx) von NordVPN unter OpenWrt ein — mit
einmaligem Zugangsdaten-Austausch, Auswahl von Land/Stadt/Server (einschließlich
Double VPN und Onion over VPN), automatischer Rotation, mehreren parallelen
VPN-Instanzen, netzweiser Traffic-Steuerung mit Kill Switch und
IPv6-Leck-Schutz sowie einer nativen LuCI-Seite.

> **Inoffiziell.** Dieses Projekt ist weder mit Nord Security verbunden noch
> von ihnen unterstützt oder befürwortet. „NordVPN“ und „NordLynx“ sind Marken
> ihrer jeweiligen Inhaber. Verwende dein eigenes NordVPN-Konto und deinen
> eigenen Zugriffstoken.

![LuCI-Übersichtsseite](docs/screenshots/overview.png)

## Architektur

Das Projekt wird als **zwei Pakete** ausgeliefert, damit der VPN-Dienst auch
ohne Weboberfläche nützlich ist und die LuCI-App ein schlankes Frontend bleibt:

- **`nordvpn-wireguard`** — das Backend (Ziel `openwrt/packages`,
  `net/nordvpn-wireguard`). ucode + procd + ein rpcd/ubus-Objekt. Erledigt den
  Zugangsdaten-Austausch, das Zwischenspeichern der Serverliste, die Erzeugung
  von WireGuard-Interface/-Peer, die Handshake-Verifizierung, die geplante
  Rotation und den Laufzeitstatus. Funktioniert über die CLI und über ubus, auch
  ohne installiertes LuCI.
- **`luci-app-nordvpn`** — das LuCI-Frontend (Ziel `openwrt/luci`,
  `applications/luci-app-nordvpn`). Eine JavaScript-Ansicht, die die
  ubus-Methoden des Backends aufruft. Führt selbst keine privilegierten
  Dateisystem- oder Netzwerkkonfigurations-Operationen aus.

Der Browser erhält niemals den Zugriffstoken oder den privaten WireGuard-Schlüssel.

## Repository-Aufbau

```
nordvpn-wireguard/                         # backend package (packages feed)
├── Makefile
├── test.sh                                # CI version smoke test
├── files/etc/config/nordvpn               # non-secret settings (owns config)
├── files/etc/init.d/nordvpn               # consolidated procd service
├── files/etc/uci-defaults/90-nordvpn-migrate
├── files/usr/bin/nordvpn-service          # uloop scheduler daemon
├── files/usr/bin/nordvpn-cache-update     # one-shot cache worker
├── files/usr/bin/nordvpn-rotate           # one-shot rotation worker
├── files/usr/share/rpcd/ucode/nordvpn.uc  # ubus object 'nordvpn'
├── files/usr/share/ucode/nordvpn/*.uc     # shared ucode modules
└── tests/                                 # offline ucode fixture/unit tests

luci-app-nordvpn/                          # LuCI frontend (luci feed)
├── Makefile
├── htdocs/luci-static/resources/view/nordvpn/overview.js
├── po/templates/nordvpn.pot
└── root/usr/share/{luci/menu.d,rpcd/acl.d}/luci-app-nordvpn.json

docs/screenshots/                          # LuCI page screenshots (README)
```

## Unterstützte Releases

- **Primär:** aktuelles OpenWrt master / Snapshots (verwendet `apk`).
- **Sekundär:** OpenWrt 25.12, sofern APIs und Abhängigkeiten passen.
- Ältere Releases nur über einen separat gepflegten Downstream-Build.

## Installation

### Aus dem signierten Paket-Feed (empfohlen)

Die CI veröffentlicht für jeden Release signierte, architekturunabhängige Pakete
unter <https://aladex.github.io/nordvpn-luci/>.

**OpenWrt 24.10 (opkg):**

```sh
wget -O /etc/opkg/keys/6bf1f0b6d25ceaad \
  https://aladex.github.io/nordvpn-luci/keys/6bf1f0b6d25ceaad
echo 'src/gz nordvpn_luci https://aladex.github.io/nordvpn-luci/packages/opkg' \
  >> /etc/opkg/customfeeds.conf
opkg update
opkg install luci-app-nordvpn        # or just nordvpn-wireguard for headless
```

**OpenWrt Snapshots / 25.x (apk):**

```sh
wget -O /etc/apk/keys/nordvpn-luci-apk.pem \
  https://aladex.github.io/nordvpn-luci/keys/nordvpn-luci-apk.pem
echo 'https://aladex.github.io/nordvpn-luci/packages/apk/packages.adb' \
  >> /etc/apk/repositories.d/customfeeds.list
apk update
apk add luci-app-nordvpn
```

Melde dich nach der Installation bei LuCI ab und wieder an, dann öffne
**VPN → NordVPN**.

### Aus einem Paket-Feed / Snapshot-Build

Baue mit dem OpenWrt-SDK für deine Zielplattform. Das Backend ist ein normales
Paket im packages-feed-Stil; die LuCI-App wird innerhalb eines
`openwrt/luci`-Checkouts gebaut.

```bash
# backend (packages feed style)
cp -r nordvpn-wireguard "$SDK/package/nordvpn-wireguard"
cd "$SDK" && ./scripts/feeds update -a && ./scripts/feeds install -a
make defconfig
make package/nordvpn-wireguard/compile

# frontend (from an openwrt/luci checkout)
cp -r luci-app-nordvpn openwrt-luci/applications/luci-app-nordvpn
# build via the luci feed as usual
```

Installiere die entstandenen Pakete auf dem Router:

```bash
apk add ./nordvpn-wireguard-*.apk ./luci-app-nordvpn-*.apk   # 25.x / snapshots
# or: opkg install ./nordvpn-wireguard_*.ipk ./luci-app-nordvpn_*.ipk   # 24.10
```

`nordvpn-wireguard` allein zu installieren ergibt einen funktionierenden
CLI-Dienst; füge `luci-app-nordvpn` für die Weboberfläche hinzu.

## Verwendung

1. Öffne LuCI → **VPN → NordVPN**.
2. Klicke auf **Zugangsdaten festlegen** (Set credentials) und füge deinen
   64-stelligen NordVPN-Zugriffstoken ein. Er wird einmalig gegen den privaten
   WireGuard-Schlüssel getauscht und **niemals gespeichert**.

   ![Zugangsdaten-Dialog](docs/screenshots/credentials-modal.png)

3. Wähle einen **Hop-Modus** (Hop mode):
   - **Einfacher Hop** (Single hop) — ein regulärer VPN-Server.
   - **Multihop** (Double VPN) — das gewählte Land ist das **Austrittsland**
     (deine sichtbare IP); der Traffic tritt über das Partnerland ein, das im
     Servernamen angezeigt wird („United Kingdom - Netherlands #10“ tritt in
     Großbritannien ein und in den Niederlanden aus).
   - **Onion over VPN** — der Traffic verlässt den VPN-Server über das
     Tor-Netzwerk. Spürbar langsamer, und einige Seiten blockieren Tor-Exit-Nodes.
     Diese Server erscheinen nie in den anderen Modi, sodass Tor immer eine
     explizite Wahl ist.

   ![Onion-over-VPN-Modus](docs/screenshots/onion-mode.png)

4. Wähle **Land** (erforderlich), optional **Stadt** und **Server**. Ländernamen
   tragen Emoji-Flaggen (schlichte Namen auf Systemen ohne Flaggen-Glyphen).
   Lass Stadt und Server auf *Automatisch*, um innerhalb des Landes zu rotieren.
5. Aktiviere optional **Automatische Rotation** und einen Zeitplan. Bei aktiver
   Rotation zeigt die Seite die konkrete **Nächste Rotation** an
   (router-geplant, angezeigt in der lokalen Zeitzone deines Browsers).

   ![Automatische Rotation](docs/screenshots/rotation.png)

6. Klicke auf **Speichern und neu verbinden** (Save and reconnect).

Einen Token bekommst du unter
<https://my.nordaccount.com/dashboard/nordvpn/manual-configuration/> →
**Generate new token** (ein nicht ablaufender Token ist in Ordnung).

Eine gespeicherte Konfiguration und ein aufgebauter Tunnel werden als
**unterschiedliche Zustände** dargestellt — die Seite behauptet nie
„Verbunden“, nur weil Einstellungen gespeichert wurden.

## Konfiguration (`/etc/config/nordvpn`)

Das Backend verwaltet hier die nicht geheimen Einstellungen; eine frische
Installation wird **deaktiviert** ausgeliefert. Ein `config instance`-Abschnitt
pro VPN-Instanz ('main' ist der Standard und trägt zugleich die gemeinsamen
Cache-Optionen).

```
config instance 'main'
	option enabled '0'
	option interface 'nordvpn'
	option routing_table ''
	option hop_mode 'single'          # 'multihop' (Double VPN) / 'onion' (via Tor)
	option country_code 'ee'
	option city_code 'ee-tallinn'
	option fixed_server ''            # pin a gateway; disables rotation
	option rotation_enabled '0'
	option rotation_mode 'interval'  # or 'time'
	option rotation_interval '360'   # minutes
	option rotation_time '04:30'     # HH:MM, router local time
	option verify_timeout '8'        # seconds to wait for a WG handshake
	option max_retries '10'          # candidate servers per rotation
	option auto_routing '1'          # route all LAN traffic via the VPN
	list source_network 'media'      # or: steer only these networks (see below)
	option killswitch '0'            # block steered traffic while VPN is down
	option block_ipv6 '1'            # block direct IPv6 (leak prevention)
	option vpn_dns 'off'             # off | standard | threat (NordVPN resolvers)
	option cache_dir ''              # empty = /tmp, shared by all instances
	option cache_refresh_interval '21600'   # seconds, background refresh
```

All dies lässt sich über die LuCI-Seite bearbeiten (das meiste unter
**Erweiterte Einstellungen** / Advanced settings):

![Erweiterte Einstellungen](docs/screenshots/advanced.png)

Das erzeugte WireGuard-Interface/-Peer liegt in `/etc/config/network` und wird
vom Backend verwaltet. Der private Schlüssel wird dort für netifd gespeichert,
erscheint aber in keiner Status-/ubus-Antwort.

## ubus-API

Alle Methoden liegen am `nordvpn`-Objekt. Lesende Methoden verändern nie etwas;
Geheimnisse werden nie zurückgegeben.

```bash
ubus call nordvpn status            # runtime state, location, handshake age
ubus call nordvpn instances         # status of every configured VPN instance
ubus call nordvpn external_ip       # public IP as seen through the tunnel
ubus call nordvpn disconnect        # take the tunnel down, pause rotation
ubus call nordvpn clear_credentials # forget the stored WireGuard key
ubus call nordvpn locations         # cached country/city tree (+ per-city counts)
ubus call nordvpn servers '{"country":"de","city":"de-berlin","hop_mode":"single"}'
ubus call nordvpn refresh_status    # cache-refresh job progress
ubus call nordvpn set_credentials '{"token":"<64-hex-token>"}'
ubus call nordvpn apply             # rebuild the peer and bring the tunnel up
ubus call nordvpn rotate_now        # one-shot rotation
ubus call nordvpn refresh_locations # start an async server-list refresh
```

`status` unterscheidet *konfiguriert* von *verbunden*: `connected` erfordert
einen WireGuard-Handshake, der jünger als 3 Minuten ist, `degraded` bedeutet,
dass das Interface aktiv ist, der Handshake aber veraltet ist, und
`rotation.next_run` ist der Epoch-Zeitpunkt der nächsten geplanten Rotation
(`null`, wenn die Rotation nicht laufen kann). Es meldet außerdem das
administrative `enabled`-Flag (eine deaktivierte Instanz ist absichtlich
abgeschaltet, nicht bloß getrennt) und `fixed` (ein Server ist angepinnt, also
ist die Rotation aus); die LuCI-Seite richtet ihre Aktions-Buttons nach beidem
aus — sie zeigt einen einzelnen Aktivieren/Deaktivieren-Umschalter und
verbirgt „Jetzt rotieren“ für einen angepinnten Tunnel.

### Mehrere VPN-Instanzen

`/etc/config/nordvpn` kann mehrere `config instance '<name>'`-Abschnitte
enthalten ('main' ist der Standard). Jede Instanz betreibt ihren eigenen Tunnel
auf ihrem eigenen Interface mit eigenen Zugangsdaten und eigenem
Rotationszeitplan — z. B. die Hauptroute über Deutschland und ein Media-Netzwerk
über Serbien. Verwende pro Instanz einen eigenen NordVPN-Zugriffstoken: die
Mehrfachnutzung eines Schlüssels von mehreren Stellen hat Berichten zufolge
dazu geführt, dass NordVPN ihn gesperrt hat. `status`, `apply`, `rotate_now` und
`set_credentials` akzeptieren ein `instance`-Argument (Standard `main`);
`create_instance`/`delete_instance` verwalten den Lebenszyklus, und
`nordvpn-rotate <name>` rotiert eine Instanz von der CLI aus. Der
Serverlisten-Cache wird gemeinsam genutzt.

Die LuCI-Seite listet jede Instanz mit ihrem Zustand, Server und der nächsten
Rotation; ein Klick auf eine Zeile wählt sie aus, und das gesamte Formular
(Zugangsdaten, Land, Rotation, Routing) gilt für die ausgewählte Instanz.
**Instanz hinzufügen** (Add instance) erstellt eine (sie erhält das Interface
`nv_<name>`), **Löschen** baut den Tunnel ab und entfernt sein Interface, die
gestempelten Firewall-Objekte und die Einstellungen; bei 'main' heißt der Button
**Zurücksetzen** (Reset) — der Abschnitt bleibt, aber jede Option kehrt auf ihren
Standard zurück. Das Statusband zeigt die tatsächliche Stadt des verbundenen
Servers und die durch den Tunnel sichtbare öffentliche IP und bietet
**Trennen** (Disconnect) an (Tunnel ab, Rotation bis zur nächsten Verbindung
pausiert). Zugangsdaten können entfernt werden, ohne die Instanz zu löschen.

Um nur einige Netzwerke durch eine Instanz zu leiten, wähle sie unter
**Gesteuerte Netzwerke** (Steered networks) im Traffic-Routing-Panel aus: das
Backend pflegt gestempelte Policy-Regeln (`in <network> lookup <table>`,
Priorität 20000) plus prohibit-Regeln, die als netzweiser Kill Switch (optional)
und IPv6-Leck-Block (standardmäßig an) wirken — sie greifen nur, wenn die Tabelle
des Tunnels den Traffic nicht bedienen kann. Damit die gesteuerte Voreinstellung
nicht lokale Ziele verschluckt, spiegelt das Backend zudem jedes lokale
IPv4-Subnetz in die Tabelle der Instanz (Interface-Subnetze, statische Routen und
die Allowed-IPs deiner eigenen WireGuard-Links; deine eigenen Routen für dasselbe
Subnetz gewinnen immer). Oder du nutzt weiterhin deine eigenen
Policy-Routing-Regeln (der manuelle Modus wird erkannt und unangetastet gelassen).

![VPN-Instanzen](docs/screenshots/instances.png)

Der Zugriff wird durch die ACL von `luci-app-nordvpn` geregelt: lesende Methoden
für Lese-Sitzungen, schreibende Methoden für Schreib-Sitzungen. Ein
schreibgeschütztes LuCI-Konto kann die Schreibmethoden nicht aufrufen, und der
rohe private Schlüssel ist weder über UCI noch über ubus erreichbar.

## Dienste und Logs

```bash
service nordvpn status
service nordvpn version        # installed version
logread -e nordvpn
```

Ein einzelner procd-überwachter Daemon (`nordvpn-service`) aktualisiert den Cache
und führt die geplante Rotation aus, wobei er `/etc/config/nordvpn` bei jedem
30-Sekunden-Tick neu einliest; eine Konfigurationsänderung startet ihn neu. Der
Rotationstakt wird in `/tmp/nordvpn_rotate_state.json` persistiert, sodass
Daemon-Neustarts den Zeitplan nicht zurücksetzen oder eine unnötige Rotation
auslösen.

### Server-Verifizierung (apply und Rotation)

Die Serverliste von NordVPN enthält tote Endpunkte, und alle WireGuard-Server in
einem Land teilen sich einen öffentlichen Schlüssel — daher bringt ein schlechter
Endpunkt das Interface trotzdem fehlerfrei „hoch“. Sowohl **apply** als auch
**Rotation** verifizieren daher jeden Kandidaten, indem sie bis zu
`verify_timeout` Sekunden auf einen tatsächlichen **WireGuard-Handshake**
(`wg show latest-handshakes`) warten, nicht durch einen Ping durch den Tunnel.
Die Rotation wechselt immer nur zu einem **anderen** Server: das aktuelle Gateway
wird aus der Kandidatenmenge ausgeschlossen, sodass eine als erfolgreich
gemeldete Rotation den Server stets gewechselt hat. Sie probiert bis zu
`max_retries` gemischte Kandidaten und stellt, falls keiner einen Handshake
abschließt, den zuletzt funktionierenden Peer wieder her, anstatt einen toten
Tunnel zu hinterlassen. Wenn die Auswahl auf keinen anderen Server als den
aktuellen passt, ist die Rotation ein No-Op und behält den funktionierenden
Tunnel. Apply verhält sich bei automatischen Auswahlen genauso. (`max_retries`
ist eine bewusste Schranke: ein Rotations-Worker muss deutlich innerhalb des
Staleness-Fensters des Locks fertig werden, damit der nächste geplante Tick
keine zweite, überlappende Rotation starten kann.)

### Rotation über Hop-Modi hinweg

Die Rotation ist Hop-Modus-bewusst — sie berücksichtigt nur Server der eigenen
Art der Instanz. Eine **Multihop**-Instanz rotiert unter Double-VPN-Servern mit
demselben **Austrittsland** (das Eintrittsland kann sich zwischen Rotationen
ändern); eine **Onion-over-VPN**-Instanz rotiert nur unter Onion-Servern;
Single-Hop mischt sich in keines von beiden ein. Da die Double-VPN- und
Onion-Pools weitaus kleiner sind als der Single-Hop-Pool, kann ein Land — oder
eine angepinnte Stadt — nur einen einzigen Server dieser Art bereitstellen; in
diesem Fall gibt es nichts, wohin rotiert werden könnte, und der aktuelle Tunnel
wird beibehalten. Onion over VPN existiert überhaupt nur in einer Handvoll
Länder, sodass die Kombination mit einem Land, das keine hat, der Rotation keine
Kandidaten lässt.

### Serverlisten-Cache

Der Daemon aktualisiert den Cache automatisch: bei seinem ersten Tick nach dem
Start aktualisiert er ihn, wenn der Cache auf der Platte älter als 24 h ist, und
danach alle `cache_refresh_interval` Sekunden (standardmäßig 6 h). Der Button
**Serverliste aktualisieren** (Refresh server list) in der UI startet denselben
Einmal-Worker (`nordvpn-cache-update`) asynchron. Cache-Schreibvorgänge sind
atomar (Temp-Datei + Umbenennen), Aktualisierungen werden per Lock serialisiert,
und eine fehlgeschlagene Aktualisierung behält den vorherigen guten Cache.

## Traffic-Routing & Firewall

Das **Traffic-Routing**-Panel entscheidet, wie der Traffic den Tunnel erreicht.
Bei jedem apply *erkennt* das Backend zunächst das aktuelle Schema:

- **Manuell** — es existieren ungestempelte Routen/Regeln, die das
  VPN-Interface referenzieren, oder eine Routing-Tabelle ist ohne Steuerung
  konfiguriert. Das Paket berührt dann niemals Routing oder Firewall; das Panel
  ist rein informativ (mit einer IPv6-Leck-Warnung, wenn das WAN IPv6 hat).

  ![Manuelles Routing erkannt](docs/screenshots/routing-manual.png)

- **Automatisch** — *Gesamten LAN-Traffic durch das VPN leiten* ist aktiviert
  (Standard bei frischen Installationen) und kein manuelles Schema wird erkannt.
  Das Backend pflegt dann: `route_allowed_ips` auf dem Peer (netifd installiert
  die Default-Route über den Tunnel und entfernt sie, wenn das Interface
  ausfällt — die WAN-Default wird nie verändert), eine Masquerading-Firewall-Zone
  für das Interface und eine Weiterleitung aus der LAN-Zone. Optionale Umschalter
  ergänzen einen **Kill Switch** (eine REJECT-Regel LAN→WAN, sodass LAN-Clients
  kein Internet bekommen, während das VPN unten ist), einen **IPv6-Block**
  (family-ipv6 REJECT LAN→WAN, standardmäßig an — NordLynx ist intern nur IPv4,
  daher würde direktes IPv6 den Tunnel umgehen) und eine **DNS-Übersteuerung** auf
  dem Interface: `standard` schiebt NordVPNs einfachen Resolver (103.86.96.100 /
  99.100) vor, `threat` schiebt NordVPN Threat Protection (103.86.96.96 / 99.99,
  blockiert Werbung und Malware auf DNS-Ebene) vor. Beide lösen nur durch den
  Tunnel auf; `off` behält den System-/WAN-Resolver.

- **Gesteuert** — bestimmte Netzwerke sind unter *Gesteuerte Netzwerke*
  (`list source_network`) angehakt. Nur ihr Traffic wird per Policy-Routing in die
  Tabelle der Instanz geleitet; der eigene Traffic des Routers und andere
  Netzwerke bleiben unberührt. Die Kill-Switch-/IPv6-Umschalter werden zu
  netzweisen prohibit-Regeln, die nur greifen, wenn der Tunnel den Traffic nicht
  bedienen kann, und jedes lokale IPv4-Subnetz wird in die Tabelle gespiegelt,
  damit VLAN-zu-VLAN und lokale Dienste erreichbar bleiben (deine eigenen Routen
  für ein Subnetz gewinnen immer).

  ![Gesteuerte Netzwerke](docs/screenshots/routing-steered.png)

Alles, was der automatische Modus erstellt, ist mit `nordvpn_managed` gestempelt;
das Deaktivieren eines Umschalters (oder des automatischen Modus) entfernt genau
die gestempelten Objekte und nichts sonst. Vom Benutzer erstellte Zonen,
Weiterleitungen, Routen und Regeln werden nie verändert. Upgrades von der alten
Lua-App behalten `auto_routing '0'`.

### Benutzerdefinierte Routing-Tabellen (manueller Modus)

Setze **Routing-Tabelle** (Advanced), um VPN-Traffic durch eine separate Tabelle
zu leiten (`ip4table`/`ip6table` auf dem Interface), und füge dann Regeln unter
**Network → Routing → Policy Routing** hinzu.

## Sicherheit

- Der Zugriffstoken wird über eine anonyme Pipe gegen den privaten Schlüssel
  getauscht (curl liest ihn aus einer Config auf `/proc/self/fd`); er erscheint
  nie in argv, einer Umgebungsvariablen, einer Temp-Datei oder Logs und wird nie
  persistiert.
- Jeder externe Befehl wird aus einer argv-Liste zusammengesetzt, wobei jedes
  Argument für die Shell einfach quotiert wird, und jeder interpolierte Wert
  (Interface-Namen, Hostnamen, Zeitpläne, Cache-Pfade) wird zuerst per Whitelist
  validiert, sodass keine Shell-Syntax eingeschleust werden kann.
- Alle ubus-Eingaben haben ein festes Schema und werden auf Bereich/Format
  validiert.
- Cache-Schreibvorgänge sind atomar (Temp-Datei + Umbenennen) und
  Aktualisierungen werden per Lock serialisiert; eine fehlgeschlagene
  Aktualisierung behält den zuletzt guten Cache.

## Upgrade / Downgrade

Ein Upgrade von der alten Lua-`luci-app-nordvpn` führt eine einmalige,
idempotente Migration (`uci-defaults`) aus, die nicht geheime Einstellungen nach
`/etc/config/nordvpn` kopiert, den bestehenden privaten Schlüssel und den aktiven
Peer bewahrt, einen etwaigen gespeicherten Token entfernt und alte Cron-Einträge
verwirft. Sie trennt keinen funktionierenden Tunnel. Ein Downgrade auf das alte
Lua-Paket wird nicht unterstützt (das neue Config-Layout wird von ihm nicht
gelesen).

## Verwandte Projekte

- [**NordVPN Lite**](https://nordvpn.com/blog/nordvpn-for-openwrt-routers/) —
  der offizielle, bewusst minimale OpenWrt-Client: eine NordLynx-Verbindung,
  CLI-/Basis-LuCI-Einrichtung. Dieses Projekt ist die Power-User-Alternative:
  mehrere parallele Instanzen mit separaten Zugangsdaten, netzweise Steuerung mit
  Kill Switch und IPv6-Leck-Schutz, geplante Rotation, die per
  WireGuard-Handshake verifiziert wird, Double VPN / Onion over VPN als explizite
  Modi und detection-first-Sicherheit rund um handgebautes Routing.
- [**NordVPN-Easy-OpenWrt**](https://github.com/tis24dev/NordVPN-Easy-OpenWrt)
  — eine shell-basierte Community-Integration mit Health-Checks und Recovery.
  Dieses Projekt verwendet stattdessen natives ucode/rpcd/procd mit einer
  Offline-Test-Suite und deckt Multi-Instanz, Steuerung und Rotation ab.
- Config-Generatoren (z. B.
  [NordVPN-WireGuard-Config-Generator](https://github.com/mustafachyi/NordVPN-WireGuard-Config-Generator))
  erzeugen statische `.conf`-Dateien und überlassen Routing, Rotation und
  Recovery dir selbst.

## Entwicklung

Offline-ucode-Tests (weder Konto noch Netzwerk nötig):

```bash
# with ucode + ucode-mod-fs + ucode-mod-math available
sh nordvpn-wireguard/tests/run.sh
```

Die CI führt statische Shell-/JSON-Prüfungen aus, LuCI-ESLint auf der JS-Ansicht,
die ucode-Tests und einen Snapshot-SDK-Build des Backends. Siehe
`.github/workflows/build.yml`.

## Lizenz

[0BSD](LICENSE) — mach damit, was du willst.
