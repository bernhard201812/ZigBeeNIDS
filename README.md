# ZigBeeNIDS - Automatisierte Erkennung von Angriffen auf ZigBee-Netzwerke
## Development of a Network Intrusion Detection System
Im Zuge meiner Diplomarbeit an der Fachhochschule St. Pölten habe ich ein Network Intrusion Detection System für ZigBee-Netzwerke entwickelt. Dieses erkennt Angriffe auf ZigBee-Netzwerke und benachrichtigt die BesitzerInnen per E-Mail. Das System ist sehr einfach in bestehende Umgebungen zu integrieren, wobei keinerlei Anpassungen hinsichtlich ZigBee notwendig sind. 

Das Setup besteht aus einem Raspberry PI 4, einem RaspBee, zshark, pyshark und dem selbst entwickelten python Programm. Derzeit wird nur auf einem ZigBee-Channel gelauscht. Sofern mehrere Channel aufgezeichnet werden können, kann der Traffic an eine zentrale Wireshark Instanz gesendet werden. Dadurch wäre es möglich mit dem NIDS alle notwendigen ZigBee-Channel zu überwachen.

Um das System verwenden zu können sind folgende Schritte notwendig:
1. Datenbank erstellen und Empfänger-Mailadresse hinterlegen (Anleitung unten)
2. Datenbankverbindung und Sender-Mailadresse in Konfigurationsfile eintragen
3. ZigBee Traffic aufzeichnen (in meinem Fall mittels RaspBee - es kann aber auch andere Hardware verwendet werden)
4. Nur falls kein RaspBee oder ConBee verwendet wird: Es muss im Code die Normalisierung in das von mir definierte ZigBee-Objekt angepasst werden. Danach funktioniert das NIDS auch mit anderer Hardware. 
5. falls RaspBee/ConBee verwendet wird - zshark starten und beim ersten Mal die Firmware des Sticks überschreiben
6. ZigBee Default-Keys in Wireshark hinterlegen (wurden geleakt und sind somit öffentlich verfügbar)
7. ZigBeeNIDS.py ausführen



Entwickler: Bernhard Bruckner, bernhard@bbruckner.at

# Implementierte Angriffe
Aus den erkannten Angriffen wurden in weiterer Folge Muster abgeleitet und diese in einer Datenbank hinterlegt. Der aufgezeichnete Traffic wird im Zuge der Verarbeitung gegen diese Muster geprüft, wobei im Falle eines Angriffs eine Benachrichtigung versendet wird. Folgende Angriffe werden vom NIDS erkannt:
* Insecure Rejoin
* Netzwerk-Key Sniffing
* Replay
* Übernahme von Geräten

Folgend werden diese Angriffe und deren Abläufe grafisch veranschaulicht. Dies soll nur einen kleinen Überblick geben, wobei für Details in meiner Diplomarbeit nachgeschlagen werden kann.

## Insecure Rejoin
Bei einem Insecure Rejoin werden der NWK Rejoin Request sowie der NWK Rejoin Response unverschlüsselt übertragen. Dieser Vorgang wird vom System erkannt und je nach Konfiguration erfolgt automatisiert eine Benachrichtigung.

<div align="center">
<img src="/pics/InsecureRejoinNIDSAblauf.png" width="50%" />
</div>


## Netzwerk-Key Sniffing
Beim Beitritt zu einem Netzwerk wird die initiale Übertragung des Netzwerk-Keys sehr häufig mit dem Default Trust Center Link Key verschlüsselt. AngreiferInnen können somit diese Übertragung entschlüsseln, wenn diese während eines Netzwerkbeitritts den Netzwerkverkehr aufzeichnen. Da dies in der Regel nicht oft vorkommen wird bedienen sich diese dem Faktor Mensch. Im ersten Schritt ermitteln die AngreiferInnen den verwendeten ZigBee-Channel mittels Sniffing. Danach senden diese kontinuierlich Störsignale aus, um die reguläre ZigBee-Kommunikation zu stören. Somit funktionieren beispielsweise das Türschloss oder die Lampen nicht mehr ordnungsgemäß, da diese die gültigen Befehle nicht mehr interpretieren können. Nun ist es sehr wahrscheinlich, dass die BenutzerInnen das Gerät aus dem Netzwerk entfernen und erneut hinzufügen in der Hoffnung, dass dieses danach wieder auf die Befehle reagiert. In diesem Zug wird der Netzwerk-Key an das Gerät übertragen und kann durch die AngreiferInnen aufgezeichnet werden. Daraus resultierend ergibt sich für das NIDS die Aufgabe einen, mit öffentlich bekannten Default Key verschlüsselten, Schlüsseltausch zu erkennen. Bei der Inbetriebnahme einer Vielzahl an neuer Geräte könnte man deswegen die Benachrichtigungen für diesen Angriff in der Datenbank temporär deaktivieren um eine Flut an Nachrichten zu vermeiden. Auf der anderen Seite ist dies ein gute Möglichkeit um die Funktionalität des NIDS zu testen.

<div align="center">
<img src="/pics/ErstuebertragungNetzwerkkeyAblaufNIDS.png" width="60%" />

</div>

## Replay
Bei einem Replay Angriff handelt es sich um das erneute Übermitteln von zuvor aufgezeichneten Nachrichten. Um unnötigen Overhead zu vermeiden, wird nicht das gesamte Paket in die Datenbank gespeichert, sondern lediglich dafür relevante Felder. Für Replay Angriffe sind vor allem diese Felder eines ZigBee-Pakets interessant:
* nwk.dst oder wpan.dst64: Empfänger Adresse des ZigBee-Pakets
* zbee\_sec\_mic: Message Integrity Code
* zbee\_sec\_counter: Frame Counter
* nwk\_seqno: Sequence Number
Durch die Kombination aus MIC, Frame Counter und Sequence Number kann ein Paket eindeutig identifiziert werden. 

<div align="center">
<img src="/pics/ReplayNIDSAblauf.png" width="50%" />

</div>


## Übernahme von Geräten
Um ein ZigBee-Gerät übernehmen zu können muss dieses dazu gebracht werden nach verfügbaren Netzwerken zu suchen. Eine sehr einfache Möglichkeit um dies zu erreichen ist das Senden des ''Reset to Factory'' Befehls, weswegen das System auch Pakete dahingehend überprüft. Beinhaltet ein ZLL Paket diesen Befehl, werden je nach Konfiguration die BenutzerInnen benachrichtigt. Unabhängig davon wird überprüft, ob es sich bei dem Paket um einen ''Network Join Request'' handelt. Um unterscheiden zu können ob es sich um einen Beitritt zum Netzwerk der BenutzerInnen oder jenes der AngreiferInnen handelt ist es möglich die eigene PAN-ID in der ''tbGeneralSettings'' unter dem Key ''PANID'' zu hinterlegen. Unterscheidet sich die eingetragene PAN-ID von jener des aktuellen Pakets deutet dies darauf hin, dass AngreiferInnen versuchen, ein oder mehrere ZigBee-Geräte zu übernehmen. Wird keine PAN-ID hinterlegt, so wird diese auf Grund der fehlenden Unterscheidungsmöglichkeit nicht auf Gleichheit überprüft. In diesem Fall wird bei jedem ''Network Join Request'' ein potenzieller Angriff erkannt.

<div align="center">
<img src="/pics/FactoryResetNIDSAblauf.png" width="50%" />

</div>


## Implementierte Prüfungen
* checkResetToFactory: Hierbei wird das ZigBee-Paket auf das Auftreten eines ResetToFactory Befehls überprüft. 
* checkInsecureRejoin: Sollte es sich bei dem Paket um einen erfolgreichen Insecure Rejoin Response handeln wird in der Tabelle tbZigBeeData nach dem zugehörigen, zuvor aufgezeichneten, Request gesucht. Ist dies der Fall hat ein Insecure Rejoin stattgefunden.
* CheckReplay: Hierbei wird die Datenbank dahingehend überprüft, ob dasselbe Paket zuvor schon einmal aufgezeichnet wurde. Dabei werden die Zieladresse (destaddress), der Message Integrity Code (zbee\_sec\_mic), der Frame Counter (zbee\_sec\_counter) sowie die Sequence Number (nwk\_seqno) auf Gleichheit überprüft. Da im Normalbetrieb dasselbe Paket nicht mehrmals übertragen wird kann man bei dessen Vorkommen davon ausgehen, dass es sich um einen Replay Angriff handelt.
* checkTransportKey: Hierbei wird beim aktuellen Paket geprüft, ob es sich um ein Transport-Key Kommando handelt, welches den Netzwerk-Key übermittelt. 
* checkTouchlinkCommissioning: In diesem Fall wird geprüft, ob das Paket einen ''Network Join Request'' enthält. Dies würde bedeuten, dass soeben versucht wird ein Gerät mittels Touchlink Commissioning in ein Netzwerk zu integrieren. 

## Datenbankdesign
Die zu speichernden Informationen werden in fünf Tabellen unterteilt:

* tbZigBeeData: Diese Tabelle beinhaltet alle für den Betrieb des NIDS notwendigen Informationen zu jedem aufgezeichneten Paket inklusive einer eigens generierten UUID, welche tabellenübergreifend als Identifier dient. Des Weiteren wird in dieser Tabelle gespeichert, ob es sich bei dem jeweiligen Paket um einen möglichen Angriff handelt. 

* tbDataThreadMapping: Alle erkannten Angriffe werden in dieser Tabelle gespeichert. Dies beinhaltet zum einen die UUID, um in weiterer Folge den Angriff einem Paket zuordnen zu können. Zum anderen wird die hinterlegte ID des Threads aus der Tabelle tbThreadSettings gespeichert. So ist es möglich im Nachhinein festzustellen welcher Angriffstyp durch welches Paket erkannt wurde.

* tbThreadSettings: Hier sind alle implementierten Angriffe beziehungsweise Gefahren hinterlegt. Hierbei kann pro Angriffstyp festgelegt werden, ob im Falle des Auftretens eine Nachricht versendet werden soll. Diese Tabelle wird beim Erstellen der Datenbankstruktur automatisiert mit Default Werten befüllt. Hierbei werden standardmäßig für alle Angriffe Benachrichtigungen ausgelöst.

* tbGeneralSettings: In dieser Tabelle können generelle Informationen in Form von Key-Value Pairs gespeichert werden. Die Empfänger-Mailadresse für die Benachrichtigungen wird hier hinterlegt. Beispielsweise können die bekannten Default Keys ebenso in dieser Tabelle hinterlegt werden. Diese sind zwar für den Betrieb derzeit nicht notwendig, da die Pakete bereits entschlüsselt von Wireshark abgeholt werden. Sollte man jedoch den Input so verändern, dass die Entschlüsselung in python mittels pyshark stattfinden soll, können diese Keys hierfür verwendet werden.


## Parametrisierung
Um das System leicht in bestehende Umgebungen integrieren zu können wurden alle notwendigen Einstellungen in einem zentralen Konfigurationsfile beziehungsweise der Datenbank selbst gespeichert. Somit sind bei der Installation und Inbetriebnahme keine Änderungen am Sourcecode notwendig. Die Einstellungen, welche sich in der Datenbank befinden, werden initial mit Default Werten erstellt und können entsprechend der eigenen Umgebung angepasst werden. 

## Logging
Die erkannten Angriffe werden zusätzlich in einem Logfile festgehalten. Ebenso kann diesem im Nachhinein entnommen werden, ob zum Zeitpunkt des Angriffs die Benachrichtigung für diesen Typ aktiv war.


# Konfiguration
Folgend werden die Befehle zur Installation des Systems sowie dessen Tests gezeigt.

## Raspberry PI Konfiguration
```
sudo apt-get install python3 python3-pip
sudo apt-get install libqt5serialport5
sudo dpkg -i zshark-1.00.05.deb
sudo apt-get install -f
```


## zshark Installation
```
wget https://phoscon.de/downloads/zshark/raspbian/zshark-1.00.05.deb
sudo dpkg -i zshark-1.00.05.deb
sudo apt-get install libqt5serialport5
```

## Wireshark Installation
```
sudo apt-get install wireshark
sudo usermod -a -G wireshark $USER
sudo chmod +x /usr/bin/dumpcap
```

## pyshark Installation
```
pip3 install pyshark==0.4.3
sudo apt-get install -y tshark
pip3 install mysql-connector-python-rf
```


## MariaDB-Server Installation 
```
sudo apt-get install mariadb-server

sudo mysql_secure_installation

Set root password? [Y/n] y
Remove anonymous users? [Y/n] y
Disallow root login remotely? [Y/n] y
Remove test database and access to it? [Y/n] y
Reload privilege tables now? [Y/n] y
```

Mit folgendem Befehl kann überprüft werden ob der mysql-Dienst auf Port 3306 lauscht.
```
ss -ltn
```

Um nun eine Verbindung zum lokalen Mysql-Server aufzubauen kann der folgende Befehl verwendet werden.
```
sudo mysql -u root -p
```

Eine Datenbank inklusive Benutzer mit entsprechenden Berechtigungen kann wie im folgenden Snippet ersichtlich erstellt werden.
```
MariaDB [(none)]> create database dbZigBeeNIDS;
MariaDB [(none)]> CREATE USER 'nids_user'@'%' 
                    IDENTIFIED BY '<your_password>';
MariaDB [(none)]> GRANT ALL privileges on dbZigBeeNIDS.* 
                    to nids_user@'%';
MariaDB [(none)]> flush privileges;
```

# Testen der Installation

## Datenbankverbindung prüfen
Um die Verbindung zur Datenbank zu überprüfen kann man sich mit dem folgenden Befehlen am lokalen MariaDB-Server anmelden. Des Weiteren kann getestet werden, ob der Benutzer ausreichend Berechtigungen hat um auf die angelegte Datenbank zuzugreifen.
```
mysql -u nids_user -p 
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| dbZigbeeNIDS       |
| information_schema |
+--------------------+
2 rows in set (0.001 sec)
```    
## Datenbankzugriff via python überprüfen
Um den Zugriff auf die Datenbank aus der python Umgebung zu testen, kann die Methode dbCon.testdbcon() verwendet werden. Folgend sieht man die relevanten Zeilen in einem Code-Snippet.
```
dbCon = db.DatabaseConnection(...)
dbCon.testdbcon()
return
```

Das erfolgreiche Ergebnis dieses Tests sieht wie folgt aus:
```
python3 ZigBeeNIDS.py 
Connected to MySQL Server version  5.5.5-10.3.31-MariaDB..
You're connected to database:  ('dbZigbeeNIDS',)
MySQL connection is closed
```

## Automatisierte Erstellung der Datenbankstruktur
Mit der Funktion dbCon.recreateDatabaseStructure() ist es möglich die gesamte Datenbankstruktur automatisiert zu erstellen.
```
python3 ZigBeeNIDS.py 
#####
MariaDB [dbZigbeeNIDS]> show tables;
+------------------------+
| Tables_in_dbZigBeeNIDS |
+------------------------+
| tbDataThreadMapping    |
| tbGeneralSettings      |
| tbThreadSettings       |
| tbZigBeeData           |
+------------------------+
4 rows in set (0.001 sec)
```

## Auslesen aus pcap File
Sollte man aus einem einem pcap-File lesen wollen, ist es notwendig dessen Pfad in der FileCapture Methode anzugeben. Des Weiteren muss bei der for Schleife darauf geachtet werden, dass die Variante mit sniff\_continously auskommentiert ist.
```
capture = pyshark.FileCapture('/<your_path>/test_reset.pcap')
```

## Test Wireshark
Nachdem zshark konfiguriert und gestartet wurde kann im nächsten Schritt Wireshark aufgerufen werden. Hierbei ist darauf zu achten, dass dieses mit root Rechten ausgeführt wird, damit das Aufzeichnen des Loopback Interfaces möglich ist.


## Installation und Verwendung von Killerbee

```
sudo apt-get install python-gtk2 python-cairo python-usb python-crypto python-serial python-dev-is-python2 libgcrypt20-dev 
git clone https://github.com/secdev/scapy   
cd scapy
sudo python3 setup.py install

git clone https://github.com/riverloopsec/killerbee/tree/master 
cd killerbee-master
sudo python3 setup.py install
```

1. Aufzeichnen des Lampe Ein Befehls und speicherns in ein pcap File 
```
zbdump -w replay_lampOn.pcap -c 11 -n 20
```

2. Replay der aufgezeichneten Pakete mittels killerbee
```
zbreplay -c 11 -r replay_lampOn.pcap -n 5
```
