# Nástroj pro anonynymizaci síťové komunikace ve formátu PCAP
Nástroj umožňuje anonymizaci síťové komunikace ve formátu PCAP pomocí anonymizační politik, 
které je možné libovolně upravovat. 

# Instalace
Nástroj vyžaduje Jazyk **Python 3** (testováno na verzi 3.8.3). 

## TShark
Důležitou závislostí aplikace je nástroj **TShark**, který je nutné nainstalovat do systému. Nástroj je možné stáhnout 
[zde](https://tshark.dev/setup/install/).

## YAJL
Důležitou závislostí aplikace je knihovna **YAJL**, kteoru je nutné nainstalovat do systému
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
použít připravený `shell` skript.
1. Vytvoření prostředí a instalace závislostí `./prepare_environment.sh`.
2. Aktivace prostředí `source venv/bin/activate`

# Spuštění nástroje
Nástroj je možné spustit příkazem `python3 main.py`, přičemž pro svoje správné fungování vyžaduje **2 povinné parametry**.
* **--config {cesta}**, kde `cesta` představuje cestu k anonymizační politice ve formátu **YAML**`
* **--files {cesta1} {cesta2}**, kde `cestaN` představuje cestu k souboru, který má být anonymizován. Souborů je možné uvést
 více a jsou odděleny mezerou. Očekávaný formát vstupních souborů je **PCAP**.
 
Příklad spuštění

`python3 main.py --config ../examples/politics/ip.yaml --files ../examples/data/ip.pcap`
 
Anonymizované soubory se nacházejí na stejném místě, jako vstupní soubory. Vstupní soubor je zkopírován a doplněn o `.anonym`
do původního jména. 

Příklad:

`../examples/data/ip.pcap` -> `../examples/data/ip.anonym.pcap`

Meta soubory anonymizace jsou vygenerovány do složky `meta` v adresáři aplikace. 
 
# Anonymizační politika
Anonymizační proces aplikace je definován anonymizační politikou. Politika je ve formátu **YAML** a její struktura
je následující : 
* `tcp_stream`: *[none|clear|clever]* | `none`: strategie validace TCP
* `reset_pools`: *[bool]* | `false`: reset mapování hodnot mezi jednotlivými soubory
* `generate_meta_files`: *[bool]* | `false`: generování souborů mapování hodnot
* `search_all_protocols`: *[bool]* | `false`: vyhledávání atributu ve všech protokolech
* `rules`: *[pravidlo]*: seznam anonymizačních pravidel

Možnosti `tcp_stream`: 
* `none`: žádná validace TCP toků neprobíhá,
* `clear`: probíhá validace porušených TCP toků, validace osamělých segmentů či neznámé komunikace zůstává nezměněna,
* `clever`: probíhá validace veškeré TCP komunikace, včetně osamělých segmntů a neznámé komunikace.

Definice pravidla (* značí povinný atribut):
* `field*`: *[string]*: název anonymizovaného atributu (očekává se stejný identifikátor jako poskytuje nástroj Wireshark nebo TShark)
* `modifier*`: název modifikátoru anonymizační metody
* `value`: hodnota předaná anonymizační metodě
* `include`: definice hodnot, které mají být anonymizovány
* `exclude`: definice hodnot, které nemají být anonymizovány
* `additional`: objekt, který slouží pro zadání dodatečných dat, které jsou dostupné v anonymizační metodě
* `value_group`: *[string]*: název skupiny pro sdílení mapování anonymizačních hodnot mezi více atributy
* `stream_unique`: *[bool]* | `false`: pravidlo je aplikováno na jednotlivé toky transportních protokolů nezávisle

Modifikátor je popsaný v následující sekci. 

Definice `include` a `exclude` umožnuje dvě verze. Pouze seznam hodnot nebo intervalů. Seznam hodnot nebo intervalů
a způsob validace pro textové řetězce:
```yaml
# výčet hodnot
include: [['Host'], ['User-Agent']]

# výčet hodnot a způsob validace
include: [
  value: [['Host'], ['User-Agent']],
  validation: 'prefix'
]

# číselné intervaly
include: [80, 8888, [0,40]]
```

Princip vyhodnocení je `exclude` a `include` je následující. Nejdříve dojde k oveření hodnot `exclude`, zda není hodnota
vyloučena z anonymizace. Pokud není vyloučena, dochází k ověření zda je k validaci připuštěna, hodnoty `include`. Pokud
nejsou hodnoty `include` definovány, je hodnota připuštěna k anonymizaci. 

**Příklady politik je možné nalézt v adresáři `examples/politics`**.

# Modifikátory
Modifikátory jsou zodpovědné za anonymizaci a validaci hodnot anonymizovaných atributů, přičemž jeden modifikátor představuje
 jednu anonymizační metodz. Modifikátory uváděny v atributu `modifier`
anonymizačního pravidla, kde se uvádí název **třídy** daného modifikátoru. Všechny modifikátory implementují rozhraní `Modifier`, které je možné nalézt v adresáři
`interfaces` v souboru `modifier.py`. Případně rozšiřují již existující modifikátory. Existující modifikátory lze nalézt v adresáři `modifiers`. 

## Přidání nového modifikátoru
Pro přídání nového modifikátoru je nutné dodržet následující podmínky:
* Implementace rozhraní `Modifier`, případně rozšíření již existujícího modifikátoru.
* Jméno modifikátoru a název souboru, ve kterém je modifikátor obsažen jsou v následujícím vztahu. Jméno modifikátoru je v tzv. **PascalCase**, přičemž název souboru je v **snake_case**. Důvodem je automatické odvozování názvu souboru modifikátoru z jeho jména, jelikož jméno modifikátoru se uvádí v položce `modifier` anonymizačního pravidla. 
* Modifikátor je umístěn v adresáři `modifiers`.

### Metody

Rozhraní obsahuje tři abstraktní třídy, které je nutné implementovat: 

* `modify_field`  je zodpovědná za samotnou anonymizaci, resp. za získání anonymizované hodnoty. Jejími parametry jsou `original_value`, jenž představuje neanonymizovanou hodnotu, `value`, který odpovídá hodnotě `value` specifikované v anonymizačním pravidle a již zmíněný `additiona_parameters`. Očekávanou návratovou hodnotou je `bytearray` představující anonymizovanou hodnotu. Případně lze vrátit `None`, čímž lze aplikaci říci, že hodnota nebyla anonymizovaná a nemá být vytvořena modifikace.
* `validate_field`  je zodpovědná za validaci hodnoty atributu před jeho anonymizací. Metoda má dva parametry `value`, jenž představuje neanonymizovanou hodnotu atributu a `additional_parameters`. Očekávanou návratovou hodnotou validační funkce je hodnota datového typu `bool`. V případě logické pravdy je atribut připuštěn k anonymizaci, v případě nepravdy je z anonymizace vyloučen.
* `transform_exclude_include_method` je užita aplikací pro transformaci položek `exclude` a `include` anonymizační pravidel do interní reprezentace vhodné pro validaci. Očekávanou návratovou hodnotou je funkce, která je aplikovatelná na každou hodnotu zmíněných položek - jako příklad lze uvést např. transformaci definice intervalu číselných hodnot, viz definice anonmizační politiky.

Modifikátor obsahuje ještě metodu `transform_output_value`, kterou je možné implementovat v případě, že chceme transformovat data ve výstupním souboru. Bez transformace jsou bytová data atributů převedena do hex podoby. Lze tak např. převést IP adresy do tečkové notace.

Pro implementaci výše uvedených abstraktních metod je možné použití metody třídy `Validator`, který se nachází v adresáři `helpers` a poskytuje validační metody. Pro implementaci metody
`modifiy_field` je možné využít funkcí dostupných v souboru `helpers.py` v adresáři `helpers`, které poskytují např. převody mezi bytovou reprezentací hodnot atributů a datovými typy či naopak.

### Atributy
Rozhraní obsahuje několik atributů, kterými lze upravovat chování anonymizace:

* `unique` definuje, zda má být anonymizovaná hodnota unikátní. Lze tak zajistit, že probíhá mapování vstupní hodnoty na anonymizovanou v poměru jedna ku jedné.
* `store_value` definuje, zda má být mapování vstupní a anonymizované hodnoty ukládáno. Mapování je možné exportovat v meta souborech, což pro některé případy nedává smysl, např. při smazání dat anonymizovaného atributu. Pokud je hodnota `false`, nelze zaručit správnou funkci
atributu `unique`.
* `meta` obsahují data, které jsou exportovány do meta souborů. Lze tu uvést např. kryptografický klíč užitý při anonymizaci.
* `exclude` a `include` obsahují transformovaná data položek `exclude` a `include` anonymizačního pravidla metodou `transform_exclude_include_method` v datovém typu `ExcludeInclude`. Typ představuje `NamedTuple` a lze jej nalézt v souboru `helpers.py`. 

# Známé problémy
Aplikace plně závisí na knihovně **YAJL**, která se na některých 64bit zařízeních chování jako 32bit a občas způsobí pád při zpracování velkých čísel. Zpravidla se
jedná o čísla větší než 32 bitů. K situaci nastává, na mém zařízení, např. při zpracování protokolu `OSPF`. Nástroj TShark v tomto případě generuje pro některé atributy protokolu
bitové masky o velikosti 64bitů a knihovna YAJL takto velké číslo nedokáže zpracovat. 