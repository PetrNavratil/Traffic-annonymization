# Nástroj pro anonynymizaci síťové komunikace ve formátu PCAP
Nástroj umožňuje anonymizaci síťové komunikace ve formátu PCAP pomocí anonymizační politik, 
které je možné libovolně upravovat. 

# Instalace
Nástroj vyžaduje Jazyk **Python 3** (testováno na verzi 3.8.3). 

Důležitou závislostí nástroje je knihovna **YALC**, kteoru je nutné nainstalovat do systému
jako sdílenou knihovnu. Knihovnu je možné stáhnout [zde](https://lloyd.github.io/yajl/).

K vytvoření virtuálního prostředí jazyka Python 3 a instalaci všech nutných závislostí je možné
použít připravený `shell` skript `prepare_environment.sh`