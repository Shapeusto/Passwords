# Budburry's Todo List — CLAUDE.md

## Prehľad projektu

Konsolová C++ aplikácia na správu úloh (Windows). Navigácia šípkami, farebné ANSI menu, úlohy uložené v XOR-šifrovanom súbore `ulohy.txt`.

## Štruktúra súborov

```
Todolist/
├── main.cpp        # Vstupný bod, hlavná slučka, dispatch
├── colors.h        # Inline ANSI escape konštanty (len .h, C++17)
├── crypto.h/.cpp   # XOR šifrovanie/dešifrovanie (kľúč = 57)
├── storage.h/.cpp  # Čítanie/zápis ulohy.txt cez crypto
├── menu.h/.cpp     # Vykreslenie menu, čítanie klávesov, enum Akcia
├── tasks.h/.cpp    # Akcie: pridajUlohu, zobrazUlohy, ukoncProgram
├── ulohy.txt       # Dátový súbor (XOR zašifrované riadky)
└── index.html      # Dokumentácia / code index
```

## Architektúra

Jednosmerné závislosti:

```
main ──▶ storage, menu, tasks
storage ──▶ crypto
menu ──▶ colors
tasks ──▶ colors, storage
```

`colors.h` je header-only s `inline const std::string` (C++17).  
`crypto.cpp` má `SIFROVACI_KLUC` ako `static const` — nie je exponovaný.

## Kompilácia

```bash
g++ -std=c++17 -o todo main.cpp crypto.cpp storage.cpp menu.cpp tasks.cpp
```

- Vyžaduje **C++17** (kvôli `inline` premenným v `colors.h`)
- Len **Windows** — používa `<conio.h>` a `<windows.h>`

## Kľúčové detaily

- **Šifra**: XOR každého bajtu s hodnotou `57` (0x39). Symetrická — tá istá funkcia šifruje aj dešifruje.
- **Navigácia**: `_getch()` z `<conio.h>`. Šípky posielajú dva bajty: `224` + `72` (hore) alebo `224` + `80` (dole). Enter = `13`.
- **Farby**: True Color ANSI (`\033[38;2;R;G;Bm`). Aktivácia cez `SetConsoleMode` s flagom `0x0004` (ENABLE_VIRTUAL_TERMINAL_PROCESSING).
- **Enum `Akcia`**: definovaný v `menu.h`, používaný v `main.cpp` pre switch dispatch.

## Čo netreba meniť

- `system("X_X 2>nul")` v `main.cpp` — zámerný hack pre aktiváciu ANSI v starších CMD verziách, nie skutočný príkaz.
- Šifrovací kľúč 57 je hardcoded — zmena by znehodnotila existujúci `ulohy.txt`.
