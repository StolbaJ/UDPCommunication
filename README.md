# UDP Communication Framework

Tento projekt implementuje jednoduchý protokol pro spolehlivý přenos souborů přes UDP v jazyce C++. Komunikuje mezi odesílatelem a příjemcem pomocí vlastního mechanismu potvrzení (ACK/NACK), kontrolního součtu CRC32 a ověření integrity dat pomocí MD5.

## Funkce

* Spolehlivý přenos přes UDP
* Detekce ztracených nebo poškozených paketů pomocí CRC32
* Ověření integrity přeneseného souboru pomocí MD5
* Opakované odesílání při ztrátě ACK
* Vlastní struktura paketů:

    * název souboru
    * hash souboru
    * velikost
    * datové pakety

## Složení projektu

* `main()` v souboru `UDP_Communication_Framework.cpp` obsahuje podmíněně kompilovaný kód pro odesílatele a příjemce (`#define SENDER` nebo `#define RECEIVER`)
* Implementace vlastního výpočtu:

    * MD5 (bez externích knihoven)
    * CRC32 (s předpočítanou tabulkou)

## Překlad

Používá WinSock2 API, doporučuje se Microsoft Visual Studio:

1. Otevři projekt jako konzolovou aplikaci.
2. Povol `ws2_32.lib` v linkeru nebo použi `#pragma comment(lib, "ws2_32.lib")` (již součástí kódu).
3. Zvol jeden z režimů (`#define SENDER` nebo `#define RECEIVER`) a zakomentuj druhý.
4. Přelož a spusť.

## Použití

### Odesílatel (`#define SENDER`)

1. Spusť program.
2. Zadej název souboru ke čtení a odeslání.
3. Program rozdělí soubor na pakety, spočítá CRC32 a MD5 hash.
4. Data jsou odesílána s potvrzením (ACK) a opakováním při chybě nebo ztrátě.

### Příjemce (`#define RECEIVER`)

1. Spusť program.
2. Čáká na metadata (název, hash, velikost) a poté na datové pakety.
3. Všechny pakety jsou ověřovány pomocí CRC32.
4. Po přijetí celého souboru se ověří MD5 hash a porovná s originálem.

## Konfigurace

IP adresa a porty jsou nastaveny ve zdrojovém kódu:

```cpp
#define TARGET_IP "192.168.136.39"
#define TARGET_PORT ...
#define LOCAL_PORT ...
```

Tyto konstanty uprav podle své sítě a role (SENDER nebo RECEIVER).

## Hash kontrola

Na konci přenosu se MD5 hash nově vygenerovaného souboru porovná s odeslaným. Pokud se shodují, přenos byl ússpěšný a data nebyla poškozena.
