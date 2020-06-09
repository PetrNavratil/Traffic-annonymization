# Nástroj pro anonynymizaci síťové komunikace ve formátu PCAP
Nástroj umožňuje anonymizaci síťové komunikace ve formátu PCAP pomocí anonymizační politik, 
které je možné libovolně upravovat. 

# Instalace
Nástroj vyžaduje Jazyk **Python 3** (testováno na verzi 3.8.3). 

## YAJL
Důležitou závislostí nástroje je knihovna **YAJL**, kteoru je nutné nainstalovat do systému
jako sdílenou knihovnu. Knihovnu je možné stáhnout [zde](https://lloyd.github.io/yajl/).

Na některých systémech dochází k nesprávné instalaci knihovny, která pak není dostupná knihovnou
JsonSlicer, kterou používá implementovaná aplikace. Situace může nastat ve chvíli, kdy je knihovna 
nainstalovaná do jiné než defaultní složky. Je proto nutné případnou instalaci poupravit
před instalací závislostí implementované aplikace. Následující postup je demonstrován pro prostředí Linux.
1. Ověřit, zda je knihovna dostupná příkazem `pkg-config --list-all | grep yajl`. Očekávaný výstup je
`yajl Yet Another JSON Library - A Portable JSON parsing and serialization library in ANSI C`. Pokud
dojde k výpisu, je možné přejít k instalaci závislostí.
2. Jinak je nutné přidat cestu k adresáři obsahující soubor `yajl.pc` do vyhledávací cesty nástroje `pkg-config`.
3. Vyhledání souboru lze provést příkazem `find / -name "yajl.pc"`.
4. Cestu adresáře lze přidat příkazem `export PKG_CONFIG_PATH=PKG_CONFIG_PATH:{cesta_adresare}`.
5. Ověřit bod 1.

## Instalace Python závislostí
Pro aplikaci je vytvoření virtuální prostředí jazyka Python, které definuje všechny nutné závislosti.
K vytvoření virtuálního prostředí jazyka Python 3 a instalaci všech nutných závislostí je možné
použít připravený `shell` skript `prepare_environment.sh`