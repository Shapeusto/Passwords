# SHAPEUSTO — Password & Task Manager

Windows console app for managing tasks and project credentials. Navigation with arrow keys, ANSI True Color UI.

## Features

- **Tasks** — add, edit, delete
- **Projects** — group credentials by project
- **Special Add** — credential templates: FTP, SFTP, Web Admin, Hosting, Database, Git, E-mail
- **AES-256-CBC encryption** with master password (PBKDF2-SHA256, 100k iterations)

## Requirements

- Windows 10+
- g++ with C++17 support (MinGW-w64 recommended)
- `windres` (comes with MinGW)

## Compilation

```bash
windres resource.rc -o resource.o
g++ -std=c++17 -o main.exe main.cpp resource.o -lbcrypt
```

## First Run

On first launch the app asks you to set a master password. This password is required every time you open the app.

## Resetting Master Password

Resetting the master password means **all data is permanently lost** (tasks and projects), because the files are encrypted with the old key.

```bash
del auth.dat ulohy.txt projekty.txt
```

Then recompile or just launch `main.exe` — it will ask for a new master password.

## Files

| File | Description |
|------|-------------|
| `main.cpp` | Full source code |
| `main.exe` | Compiled binary |
| `auth.dat` | Salt (16B) + password verifier (32B) |
| `ulohy.txt` | Encrypted tasks |
| `projekty.txt` | Encrypted projects & credentials |
| `icon.ico` | App icon |
| `resource.rc` | Resource file for icon embedding |

## Security

- Key derivation: **PBKDF2-SHA256**, 100 000 iterations, random 16B salt
- Encryption: **AES-256-CBC**, random IV per file write
- `auth.dat` stores only `SHA-256(key)` — the key itself is never saved
- Wrong password allows 3 attempts, then exits
