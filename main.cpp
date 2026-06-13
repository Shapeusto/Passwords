#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <windows.h>
#include <conio.h> // Obsahuje funkciu _getch() na čítanie stlačených klávesov bez Enteru
#include <bcrypt.h>
#include <cstdint>
#pragma comment(lib, "bcrypt.lib")

// =============================================================================
// FARBY
// True Color ANSI escape sekvencie (\033[38;2;R;G;Bm = farba textu,
//                                    \033[48;2;R;G;Bm = farba pozadia)
// =============================================================================
const std::string ZLTA    = "\033[38;2;219;255;0m";   // #DBFF00
const std::string CERVENA = "\033[38;2;253;114;45m";  // #FD722D
const std::string RESET   = "\033[0m";
const std::string DARK    = "\033[38;2;59;59;59m";

// Zvýraznenie vybraného riadku — farebné pozadie, čierny text
const std::string REVERZ_ZLTA    = "\033[48;2;219;255;0m\033[38;2;0;0;0m";
const std::string REVERZ_CERVENA = "\033[48;2;253;114;45m\033[38;2;0;0;0m";

void tlacLogo(bool sGradientom = true) {
    static const std::string logo[3][9] = {
        { "┏━┓", "╻ ╻", "┏━┓", "┏━┓", "┏━╸", "╻ ╻", "┏━┓", "╺┳╸", "┏━┓" },
        { "┗━┓", "┣━┫", "┣━┫", "┣━┛", "┣╸ ", "┃ ┃", "┗━┓", " ┃ ", "┃ ┃" },
        { "┗━┛", "╹ ╹", "╹ ╹", "╹  ", "┗━╸", "┗━┛", "┗━┛", " ╹ ", "┗━┛" }
    };

    static const std::string farbyGradientu[9] = {
        "\033[38;2;219;255;0m", // #DBFF00
        "\033[38;2;202;253;0m",
        "\033[38;2;186;252;0m",
        "\033[38;2;169;250;0m",
        "\033[38;2;152;248;0m",
        "\033[38;2;135;247;0m",
        "\033[38;2;119;245;0m",
        "\033[38;2;102;244;0m",
        "\033[38;2;85;242;0m"  // #55F200
    };

    for (int r = 0; r < 3; ++r) {
        for (int c = 0; c < 9; ++c) {
            if (sGradientom) {
                std::cout << farbyGradientu[c];
            } else {
                std::cout << DARK;
            }
            std::cout << logo[r][c];
        }
        std::cout << "\n";
    }
    std::cout << RESET;
}



// =============================================================================
// SIFROVANIE
// PBKDF2-SHA256 (100000 iteracii, nahodny salt 16B) → AES-256 kluc (32B).
// AES-256-CBC s nahodnym IV (16B) pre kazdy zapis suboru.
// auth.dat format: salt(16B) + SHA-256(kluc)(32B)
// Sifrovane subory format: IV(16B) + AES-CBC ciphertext s PKCS7 paddingom
// =============================================================================
std::vector<uint8_t> KLUC; // AES-256 kluc (32B) — nastaveny pocas inicializacie

// SHA-256 pomocna funkcia — pouzivana na verifikacny hash v auth.dat
std::vector<uint8_t> sha256(const std::string& data) {
    std::vector<uint8_t> hash(32, 0);
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0) {
        if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) == 0) {
            BCryptHashData(hHash, (PUCHAR)data.c_str(), (ULONG)data.size(), 0);
            BCryptFinishHash(hHash, hash.data(), 32, 0);
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    return hash;
}

// PBKDF2-SHA256 — pomalý KDF odolny voci brute-force (100000 iteracii ~200ms)
std::vector<uint8_t> pbkdf2(const std::string& heslo, const std::vector<uint8_t>& salt) {
    std::vector<uint8_t> kluc(32, 0);
    BCRYPT_ALG_HANDLE hPrf = NULL;
    if (BCryptOpenAlgorithmProvider(&hPrf, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) == 0) {
        BCryptDeriveKeyPBKDF2(hPrf,
            (PUCHAR)heslo.c_str(), (ULONG)heslo.size(),
            (PUCHAR)salt.data(),   (ULONG)salt.size(),
            100000, kluc.data(), 32, 0);
        BCryptCloseAlgorithmProvider(hPrf, 0);
    }
    return kluc;
}

// Citanie hesla so skrytym vstupom — zobrazuje * namiesto znakov, ESC = zrusenie
std::string citajHesloSkryte() {
    std::string heslo;
    int c;
    while ((c = _getch()) != 13) {
        if (c == 27) { std::cout << std::endl; return ""; }
        if (c == 8 && !heslo.empty()) {
            heslo.pop_back();
            std::cout << "\b \b";
        } else if (c >= 32 && c < 127) {
            heslo += (char)c;
            std::cout << '*';
        }
    }
    std::cout << std::endl;
    return heslo;
}

// AES-256-CBC sifrovanie — vracia IV(16B) + ciphertext (PKCS7 padding)
std::vector<uint8_t> aesEncrypt(const std::string& plaintext) {
    std::vector<uint8_t> result;
    std::vector<uint8_t> iv(16);
    BCryptGenRandom(NULL, iv.data(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return result;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      (ULONG)((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(WCHAR)), 0);
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, KLUC.data(), 32, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0); return result;
    }

    // Zistenie dlzky vystupu s paddingom
    ULONG outLen = 0;
    std::vector<uint8_t> ivTmp = iv;
    BCryptEncrypt(hKey, (PUCHAR)plaintext.c_str(), (ULONG)plaintext.size(),
                  NULL, ivTmp.data(), 16, NULL, 0, &outLen, BCRYPT_BLOCK_PADDING);

    std::vector<uint8_t> ciphertext(outLen);
    ivTmp = iv;
    ULONG bytesOut = 0;
    BCryptEncrypt(hKey, (PUCHAR)plaintext.c_str(), (ULONG)plaintext.size(),
                  NULL, ivTmp.data(), 16, ciphertext.data(), outLen, &bytesOut, BCRYPT_BLOCK_PADDING);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + bytesOut);
    return result;
}

// AES-256-CBC desifrovanie — ocakava IV(16B) + ciphertext, vracia plaintext
std::string aesDecrypt(const std::vector<uint8_t>& data) {
    if (data.size() <= 16) return "";
    std::vector<uint8_t> iv(data.begin(), data.begin() + 16);
    std::vector<uint8_t> ciphertext(data.begin() + 16, data.end());

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    std::string result;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return result;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      (ULONG)((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(WCHAR)), 0);
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, KLUC.data(), 32, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0); return result;
    }

    std::vector<uint8_t> plaintext(ciphertext.size());
    ULONG bytesOut = 0;
    NTSTATUS status = BCryptDecrypt(hKey, ciphertext.data(), (ULONG)ciphertext.size(),
                                     NULL, iv.data(), 16, plaintext.data(),
                                     (ULONG)ciphertext.size(), &bytesOut, BCRYPT_BLOCK_PADDING);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (status == 0 && bytesOut > 0)
        result = std::string(plaintext.begin(), plaintext.begin() + bytesOut);
    return result;
}

// Zapis zasifrovaneho obsahu do suboru (binary: IV + ciphertext)
void ulozEncrypted(const std::string& obsah, const std::string& cesta) {
    auto enc = aesEncrypt(obsah);
    if (enc.empty()) return;
    std::ofstream f(cesta, std::ios::binary);
    if (f.is_open()) f.write((char*)enc.data(), enc.size());
}

// Citanie a desifrovanie obsahu suboru — vracia plaintext alebo ""
std::string nacitajDecrypted(const std::string& cesta) {
    std::ifstream f(cesta, std::ios::binary);
    if (!f.is_open()) return "";
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
    return aesDecrypt(data);
}

// Inicializacia sifrovania — nastavenie alebo overenie master hesla.
// Vracia true ak je autentifikacia uspesna.
bool inicializujSifrovanie() {
    const std::string authSubor = "auth.dat";
    std::vector<uint8_t> salt(16, 0);
    std::vector<uint8_t> ulozenaHash(32, 0);
    bool prveSpustenie = false;

    std::ifstream fin(authSubor, std::ios::binary);
    if (fin.is_open()) {
        fin.read((char*)salt.data(), 16);
        fin.read((char*)ulozenaHash.data(), 32);
        prveSpustenie = (fin.gcount() < 32);
        fin.close();
    } else {
        prveSpustenie = true;
    }

    if (prveSpustenie) {
        system("cls");
        std::cout << "\n" << ZLTA << "  First run — set master password\n\n" << RESET;
        std::cout << ZLTA << "  Master password: " << RESET;
        std::string heslo = citajHesloSkryte();
        if (heslo.empty()) {
            std::cout << CERVENA << "  Password cannot be empty.\n" << RESET;
            Sleep(1500); return false;
        }
        std::cout << ZLTA << "  Confirm password: " << RESET;
        std::string heslo2 = citajHesloSkryte();
        if (heslo != heslo2) {
            std::cout << CERVENA << "  Passwords do not match.\n" << RESET;
            Sleep(1500); return false;
        }

        // Nahodny salt + PBKDF2
        BCryptGenRandom(NULL, salt.data(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        KLUC = pbkdf2(heslo, salt);

        // Verifikacny hash = SHA-256(kluc) — nie kluc samotny
        std::string klucStr(KLUC.begin(), KLUC.end());
        std::vector<uint8_t> verHash = sha256(klucStr);

        std::ofstream fout(authSubor, std::ios::binary);
        fout.write((char*)salt.data(), 16);
        fout.write((char*)verHash.data(), 32);

        std::cout << ZLTA << "\n  Password set. Press any key...\n" << RESET;
        _getch();
        return true;
    }

    // Overenie hesla — max 3 pokusy
    for (int pokus = 0; pokus < 3; pokus++) {
        system("cls");
        std::cout << "\n";
        tlacLogo(true);
        std::cout << "\n";
        if (pokus > 0)
            std::cout << CERVENA << "  Wrong password. " << (3 - pokus) << " attempt(s) remaining.\n\n" << RESET;
        std::cout << ZLTA << "  Master password: " << RESET;
        std::string heslo = citajHesloSkryte();
        if (heslo.empty()) return false;

        std::vector<uint8_t> kandidatKluc = pbkdf2(heslo, salt);
        std::string klucStr(kandidatKluc.begin(), kandidatKluc.end());
        std::vector<uint8_t> kandidatHash = sha256(klucStr);

        if (kandidatHash == ulozenaHash) {
            KLUC = kandidatKluc;
            return true;
        }
        Sleep(1000);
    }

    system("cls");
    std::cout << CERVENA << "\n  Sorry pal, you failed too many times.\n" << RESET;
    Sleep(2000);
    return false;
}


// =============================================================================
// ULOZISKO — ULOHY
// ulohy.txt: IV(16B) + AES-256-CBC(plaintext riadkov oddelených \n)
// =============================================================================
void ulozDoSuboru(const std::vector<std::string>& ulohy) {
    std::string obsah;
    for (const auto& u : ulohy) obsah += u + "\n";
    ulozEncrypted(obsah, "ulohy.txt");
}

std::vector<std::string> nacitajZoSuboru() {
    std::vector<std::string> ulohy;
    std::istringstream ss(nacitajDecrypted("ulohy.txt"));
    std::string riadok;
    while (std::getline(ss, riadok))
        if (!riadok.empty()) ulohy.push_back(riadok);
    return ulohy;
}


// =============================================================================
// ULOZISKO — PROJEKTY
// Format projekty.txt pre kazdy projekt:
//   riadok 1 = zasifrovany nazov projektu
//   riadok 2 = zasifrovany pocet poloziek (ako string)
//   nasleduju pary riadkov: zasifrovany nazov polozky + zasifrovane heslo
// =============================================================================
struct PolozkaHesla {
    std::string nazov; // napr. "Mail", "FTP", "Admin"
    std::string heslo;
};

struct Projekt {
    std::string nazov;
    std::vector<PolozkaHesla> polozky;
};

void ulozProjektyDoSuboru(const std::vector<Projekt>& projekty) {
    std::string obsah;
    for (const Projekt& p : projekty) {
        obsah += p.nazov + "\n";
        obsah += std::to_string(p.polozky.size()) + "\n";
        for (const PolozkaHesla& pol : p.polozky) {
            obsah += pol.nazov + "\n";
            obsah += pol.heslo  + "\n";
        }
    }
    ulozEncrypted(obsah, "projekty.txt");
}

std::vector<Projekt> nacitajProjektyZoSuboru() {
    std::vector<Projekt> projekty;
    std::istringstream ss(nacitajDecrypted("projekty.txt"));
    std::string riadok;
    while (std::getline(ss, riadok)) {
        Projekt p;
        p.nazov = riadok;
        std::string pocetStr;
        if (!std::getline(ss, pocetStr)) break;
        int pocet = 0;
        try { pocet = std::stoi(pocetStr); }
        catch (...) { break; }
        for (int i = 0; i < pocet; i++) {
            std::string n, h;
            if (!std::getline(ss, n) || !std::getline(ss, h)) break;
            p.polozky.push_back({ n, h });
        }
        projekty.push_back(p);
    }
    return projekty;
}


// =============================================================================
// SPRAVA ULOH — interaktívny zoznam
// Navigácia šípkami, ENTER = upraviť vybranú úlohu, DEL = vymazať, ESC = späť
// =============================================================================
std::string ziskajAktualnyCas() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    auto formatTwoDigits = [](int val) {
        return (val < 10 ? "0" : "") + std::to_string(val);
    };
    
    return formatTwoDigits(st.wDay) + "." +
           formatTwoDigits(st.wMonth) + "." +
           std::to_string(st.wYear) + " " +
           formatTwoDigits(st.wHour) + ":" +
           formatTwoDigits(st.wMinute) + ":" +
           formatTwoDigits(st.wSecond);
}

void spravujUlohy(std::vector<std::string>& ulohy) {
    int cursor = 0;

    while (true) {
        system("cls");
        std::cout << ZLTA << "--- YOUR TASKS ---\n" << RESET << std::endl;

        if (ulohy.empty()) {
            std::cout << DARK << "No tasks yet.\n" << RESET;
        } else {
            for (size_t i = 0; i < ulohy.size(); i++) {
                std::string u = ulohy[i];
                std::string textUlohy = u;
                std::string casVytvorenia = "";
                size_t pos = u.find('\t');
                if (pos != std::string::npos) {
                    textUlohy = u.substr(0, pos);
                    casVytvorenia = u.substr(pos + 1);
                }

                if ((int)i == cursor) {
                    if (!casVytvorenia.empty()) {
                        std::cout << REVERZ_ZLTA << " > " << i + 1 << ". " << textUlohy << " (" << casVytvorenia << ") < " << RESET << "\n";
                    } else {
                        std::cout << REVERZ_ZLTA << " > " << i + 1 << ". " << textUlohy << " < " << RESET << "\n";
                    }
                }
                else {
                    if (!casVytvorenia.empty()) {
                        std::cout << ZLTA << "   " << i + 1 << ". " << textUlohy << "  " << DARK << "(" << casVytvorenia << ")" << RESET << "\n";
                    } else {
                        std::cout << ZLTA << "   " << i + 1 << ". " << textUlohy << "   " << RESET << "\n";
                    }
                }
            }
        }

        std::cout << DARK << "\n[UP/DOWN = navigate]  [A = add]  [ENTER = edit]  [DEL = delete]  [ESC = back]" << RESET;

        int klaves = _getch();

        if (klaves == 0 || klaves == 224) {
            klaves = _getch();
            if (klaves == 72) { // Šípka HORE
                cursor--;
                if (cursor < 0) cursor = (int)ulohy.size() - 1;
            }
            else if (klaves == 80) { // Šípka DOLE
                cursor++;
                if (cursor >= (int)ulohy.size()) cursor = 0;
            }
            else if (klaves == 83) { // DEL — vymazať vybranú úlohu
                std::cout << "\n" << CERVENA << "Delete this task? [Y / N]: " << RESET;
                int confirm = _getch();
                if (confirm == 'y' || confirm == 'Y') {
                    ulohy.erase(ulohy.begin() + cursor);
                    if (cursor >= (int)ulohy.size() && cursor > 0) cursor--;
                    ulozDoSuboru(ulohy);
                }
            }
        }
        else if (klaves == 'a' || klaves == 'A') { // A — pridať novú úlohu
            system("cls");
            std::cout << ZLTA << "Enter task: " << RESET;
            std::string nova_uloha;
            std::getline(std::cin, nova_uloha);
            if (!nova_uloha.empty()) {
                ulohy.push_back(nova_uloha + "\t" + ziskajAktualnyCas());
                cursor = (int)ulohy.size() - 1;
                ulozDoSuboru(ulohy);
            }
        }
        else if (klaves == 13 && !ulohy.empty()) { // Enter — upraviť vybranú úlohu
            system("cls");
            std::cout << ZLTA << "Edit task" << RESET << DARK << " (empty Enter = keep):\n" << RESET;
            
            std::string u = ulohy[cursor];
            std::string textUlohy = u;
            std::string casVytvorenia = "";
            size_t pos = u.find('\t');
            if (pos != std::string::npos) {
                textUlohy = u.substr(0, pos);
                casVytvorenia = u.substr(pos + 1);
            }

            std::cout << DARK << "Current: " << RESET << textUlohy << "\n";
            std::cout << ZLTA << "New: " << RESET;
            std::string nova;
            std::getline(std::cin, nova);
            if (!nova.empty()) {
                if (!casVytvorenia.empty()) {
                    ulohy[cursor] = nova + "\t" + casVytvorenia;
                } else {
                    ulohy[cursor] = nova + "\t" + ziskajAktualnyCas();
                }
                ulozDoSuboru(ulohy);
            }
        }
        else if (klaves == 27 || klaves == 8) { // ESC — späť do menu
            break;
        }
    }
}


// =============================================================================
// SPRAVA PROJEKTOV — interaktívne zoznamy
// spravujProjekt  — detail projektu: položky s heslami
// spravujProjekty — zoznam všetkých projektov
// =============================================================================

// Vrati true ak ma byt hodnota polozky maskovana hviezdickami.
// Defaultne maskuje (manualne polozky su vzdy hesla), ale znamy necitlive nazvy poli sablon nechava v plaintext.
bool maSkovat(const std::string& nazov) {
    static const std::vector<std::string> necitlive = {
        "Host / IP", "Port", "Username", "Username / Email",
        "Login URL", "Panel URL", "Repository URL",
        "Host / Server", "Database name", "Server", "Email address"
    };
    for (const auto& n : necitlive) {
        if (nazov == n) return false;
    }
    return true;
}

// Skopíruje text do Windows schránky (Ctrl+V ho potom prilepí kdekoľvek)
// Zamaskuje heslo — zobrazí prvý a posledný znak, medzi tým ******
std::string maskujHeslo(const std::string& heslo) {
    if (heslo.size() <= 2) return std::string(heslo.size(), '*');
    return std::string(1, heslo.front()) + "******" + std::string(1, heslo.back());
}

void skopirujDoSchranky(const std::string& text) {
    if (OpenClipboard(NULL)) {
        EmptyClipboard();
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
        if (hMem) {
            memcpy(GlobalLock(hMem), text.c_str(), text.size() + 1);
            GlobalUnlock(hMem);
            SetClipboardData(CF_TEXT, hMem);
        }
        CloseClipboard();
    }
}

// Sablony pre special vkladanie — kazda sablona ma nazov a zoznam poli (nazov + ci je volitelne)
void specialneVlozenie(Projekt& projekt, std::vector<Projekt>& vsetkyProjekty) {
    struct Pole { std::string nazov; bool volitelne; };
    struct Sablona { std::string nazov; std::vector<Pole> polia; };

    std::vector<Sablona> sablony = {
        { "FTP / FTPS",              { {"Host / IP", false}, {"Port", false}, {"Username", false}, {"Password", false} } },
        { "SFTP / SSH",              { {"Host / IP", false}, {"Port", false}, {"Username", false}, {"Password / SSH Key", false} } },
        { "Web Admin (CMS / Web)",   { {"Login URL", false}, {"Username / Email", false}, {"Password", false} } },
        { "Hosting Control Panel",   { {"Panel URL", false}, {"Username", false}, {"Password", false}, {"2FA Code", true} } },
        { "Database (MySQL/pgSQL)",  { {"Host / Server", false}, {"Database name", false}, {"Username", false}, {"Password", false} } },
        { "Git (GitHub / GitLab)",   { {"Repository URL", false}, {"Username", false}, {"PAT / SSH Key", false} } },
        { "E-mail (SMTP / IMAP)",    { {"Server", false}, {"Port", false}, {"Email address", false}, {"Password", false} } }
    };

    int cursor = 0;

    // Vyber sablony
    while (true) {
        system("cls");
        std::cout << ZLTA << "--- SPECIAL ADD ---\n" << RESET << std::endl;
        for (size_t i = 0; i < sablony.size(); i++) {
            if ((int)i == cursor)
                std::cout << REVERZ_ZLTA << " > " << sablony[i].nazov << " < " << RESET << "\n";
            else
                std::cout << ZLTA << "   " << sablony[i].nazov << RESET << "\n";
        }
        std::cout << DARK << "\n[UP/DOWN = navigate]  [ENTER = select]  [ESC = back]" << RESET;

        int k = _getch();
        if (k == 0 || k == 224) {
            k = _getch();
            if (k == 72) { cursor--; if (cursor < 0) cursor = (int)sablony.size() - 1; }
            else if (k == 80) { cursor++; if (cursor >= (int)sablony.size()) cursor = 0; }
        }
        else if (k == 13) { break; }
        else if (k == 27 || k == 8) { return; }
    }

    // Vyplnenie poli vybranej sablony
    Sablona& s = sablony[cursor];
    system("cls");
    std::cout << ZLTA << "--- " << s.nazov << " ---\n" << RESET;
    std::cout << DARK << "(press Enter to skip optional fields)\n\n" << RESET;

    std::vector<PolozkaHesla> nove;
    for (auto& pole : s.polia) {
        std::cout << ZLTA << pole.nazov;
        if (pole.volitelne) std::cout << DARK << " (optional)";
        std::cout << RESET << ": ";
        std::string val;
        std::getline(std::cin, val);
        if (!val.empty()) {
            nove.push_back({ pole.nazov, val });
        }
    }

    if (!nove.empty()) {
        // Vloz separator header pred skupinu (heslo="" = header, nie klasicka polozka)
        nove.insert(nove.begin(), { "--- " + s.nazov + " ---", "" });
        for (auto& pol : nove) projekt.polozky.push_back(pol);
        ulozProjektyDoSuboru(vsetkyProjekty);
    }
}

// Detail projektu — zobrazenie a správa položiek hesiel jedného projektu
void spravujProjekt(Projekt& projekt, std::vector<Projekt>& vsetkyProjekty) {
    int cursor = 0;
    std::string sprava = "";

    while (true) {
        system("cls");
        std::cout << ZLTA << "--- " << projekt.nazov << " ---\n" << RESET << std::endl;

        if (projekt.polozky.empty()) {
            std::cout << DARK << "No entries. Press A to add.\n" << RESET;
        } else {
            for (size_t i = 0; i < projekt.polozky.size(); i++) {
                bool jeHeader = projekt.polozky[i].heslo.empty();
                if (jeHeader) {
                    // Separator — nadpis skupiny bez hesla
                    if (i > 0) std::cout << "\n"; // prazdny riadok vzdy (okrem prveho) — zabraňuje skakaniu layoutu
                    if ((int)i == cursor)
                        std::cout << REVERZ_ZLTA << " > " << projekt.polozky[i].nazov << " < " << RESET << "\n";
                    else
                        std::cout << DARK << "  " << projekt.polozky[i].nazov << RESET << "\n";
                } else {
                    std::string zobraz = maSkovat(projekt.polozky[i].nazov)
                        ? maskujHeslo(projekt.polozky[i].heslo)
                        : projekt.polozky[i].heslo;
                    if ((int)i == cursor)
                        std::cout << REVERZ_ZLTA << " > " << projekt.polozky[i].nazov << ": " << zobraz << " < " << RESET << "\n";
                    else
                        std::cout << ZLTA << "   " << projekt.polozky[i].nazov << RESET << ": " << zobraz << "\n";
                }
            }
        }

        std::cout << DARK << "\n[UP/DOWN = navigate]  [A = add]  [S = special add]  [ENTER = edit]  [DEL = delete]  [C = copy]  [ESC = back]" << RESET;

        if (!sprava.empty()) {
            std::cout << "\n" << ZLTA << sprava << RESET;
            sprava = "";
        }

        int klaves = _getch();

        if (klaves == 0 || klaves == 224) {
            klaves = _getch();
            if (klaves == 72) { // Šípka HORE
                if (!projekt.polozky.empty()) {
                    cursor--;
                    if (cursor < 0) cursor = (int)projekt.polozky.size() - 1;
                }
            }
            else if (klaves == 80) { // Šípka DOLE
                if (!projekt.polozky.empty()) {
                    cursor++;
                    if (cursor >= (int)projekt.polozky.size()) cursor = 0;
                }
            }
            else if (klaves == 83 && !projekt.polozky.empty()) { // DEL
                bool jeHeader = projekt.polozky[cursor].heslo.empty();
                if (jeHeader) {
                    // DEL na header — zmazanie celej sekcie (header + vsetky jej zaznamy)
                    int koniec = cursor + 1;
                    while (koniec < (int)projekt.polozky.size() && !projekt.polozky[koniec].heslo.empty())
                        koniec++;
                    std::cout << "\n" << CERVENA << "Delete entire section? [Y / N]: " << RESET;
                    int confirm = _getch();
                    if (confirm == 'y' || confirm == 'Y') {
                        projekt.polozky.erase(projekt.polozky.begin() + cursor,
                                              projekt.polozky.begin() + koniec);
                        if (cursor >= (int)projekt.polozky.size())
                            cursor = std::max(0, (int)projekt.polozky.size() - 1);
                        ulozProjektyDoSuboru(vsetkyProjekty);
                    }
                } else {
                    // DEL na zaznam — zmazanie zaznamu + cistenie prazdnych sekcii
                    std::cout << "\n" << CERVENA << "Delete this entry? [Y / N]: " << RESET;
                    int confirm = _getch();
                    if (confirm == 'y' || confirm == 'Y') {
                        projekt.polozky.erase(projekt.polozky.begin() + cursor);
                        if (cursor >= (int)projekt.polozky.size() && cursor > 0) cursor--;
                        // Zmazanie headerov ktore ostali bez zaznamov
                        for (int j = (int)projekt.polozky.size() - 1; j >= 0; j--) {
                            if (projekt.polozky[j].heslo.empty()) {
                                bool prazdna = (j + 1 >= (int)projekt.polozky.size() ||
                                                projekt.polozky[j + 1].heslo.empty());
                                if (prazdna) {
                                    projekt.polozky.erase(projekt.polozky.begin() + j);
                                    if (cursor >= j) cursor = std::max(0, cursor - 1);
                                }
                            }
                        }
                        ulozProjektyDoSuboru(vsetkyProjekty);
                    }
                }
            }
        }
        else if ((klaves == 'a' || klaves == 'A')) { // A — pridať novú položku
            system("cls");
            std::cout << ZLTA << "Entry name (e.g. Mail, FTP, Admin): " << RESET;
            std::string nazov;
            std::getline(std::cin, nazov);
            if (!nazov.empty()) {
                std::cout << ZLTA << "Password: " << RESET;
                std::string heslo;
                std::getline(std::cin, heslo);
                if (!heslo.empty()) {
                    // Najdi existujucu "--- Other ---" sekciu kdekolyvek v liste
                    int otherIdx = -1;
                    for (int j = 0; j < (int)projekt.polozky.size(); j++) {
                        if (projekt.polozky[j].heslo.empty() && projekt.polozky[j].nazov == "--- Other ---") {
                            otherIdx = j; break;
                        }
                    }
                    if (otherIdx >= 0) {
                        // Vloz na koniec existujucej "--- Other ---" sekcie
                        int insertPos = otherIdx + 1;
                        while (insertPos < (int)projekt.polozky.size() && !projekt.polozky[insertPos].heslo.empty())
                            insertPos++;
                        projekt.polozky.insert(projekt.polozky.begin() + insertPos, { nazov, heslo });
                        cursor = insertPos;
                    } else {
                        // "--- Other ---" este neexistuje — pridaj na koniec
                        projekt.polozky.push_back({ "--- Other ---", "" });
                        projekt.polozky.push_back({ nazov, heslo });
                        cursor = (int)projekt.polozky.size() - 1;
                    }
                    ulozProjektyDoSuboru(vsetkyProjekty);
                    sprava = "Entry added!";
                }
            }
        }
        else if (klaves == 13 && !projekt.polozky.empty() && !projekt.polozky[cursor].heslo.empty()) { // Enter — upraviť vybranú položku (nie header)
            system("cls");
            std::cout << ZLTA << "Edit entry" << RESET << DARK << " (empty Enter = keep):\n" << RESET;

            std::cout << DARK << "Current name: " << RESET << projekt.polozky[cursor].nazov << "\n";
            std::cout << ZLTA << "New name: " << RESET;
            std::string novyNazov;
            std::getline(std::cin, novyNazov);

            std::cout << DARK << "Current password: " << RESET << projekt.polozky[cursor].heslo << "\n";
            std::cout << ZLTA << "New password: " << RESET;
            std::string noveHeslo;
            std::getline(std::cin, noveHeslo);

            if (!novyNazov.empty()) projekt.polozky[cursor].nazov = novyNazov;
            if (!noveHeslo.empty()) projekt.polozky[cursor].heslo = noveHeslo;

            if (!novyNazov.empty() || !noveHeslo.empty()) {
                ulozProjektyDoSuboru(vsetkyProjekty);
            }
        }
        else if (klaves == 's' || klaves == 'S') { // S — special vkladanie zo sablony
            size_t predtym = projekt.polozky.size();
            specialneVlozenie(projekt, vsetkyProjekty);
            if (projekt.polozky.size() > predtym) {
                cursor = (int)projekt.polozky.size() - 1;
                sprava = "Entries added!";
            }
        }
        else if ((klaves == 'c' || klaves == 'C') && !projekt.polozky.empty()) { // C — kopírovať heslo
            if (!projekt.polozky[cursor].heslo.empty()) {
                skopirujDoSchranky(projekt.polozky[cursor].heslo);
                sprava = "Password copied!";
            }
        }
        else if (klaves == 27 || klaves == 8) { // ESC — späť na zoznam projektov
            break;
        }
    }
}

// Zoznam projektov — výber a správa projektov
void spravujProjekty(std::vector<Projekt>& projekty) {
    int cursor = 0;

    while (true) {
        system("cls");
        std::cout << ZLTA << "--- PROJECTS ---\n" << RESET << std::endl;

        if (projekty.empty()) {
            std::cout << DARK << "No projects yet.\n" << RESET;
        } else {
            for (size_t i = 0; i < projekty.size(); i++) {
                std::string pocet = "(" + std::to_string(projekty[i].polozky.size()) + " items)";
                if ((int)i == cursor)
                    std::cout << REVERZ_ZLTA << " > " << projekty[i].nazov << "  " << pocet << " < " << RESET << "\n";
                else
                    std::cout << ZLTA << "   " << projekty[i].nazov << "  " << DARK << pocet << RESET << "\n";
            }
        }

        std::cout << DARK << "\n[UP/DOWN = navigate]  [W/E = move up/down]  [A = add]  [ENTER = open]  [DEL = delete]  [ESC = back]" << RESET;

        int klaves = _getch();

        if (klaves == 0 || klaves == 224) {
            klaves = _getch();
            if (klaves == 72) { // Šípka HORE
                cursor--;
                if (cursor < 0) cursor = (int)projekty.size() - 1;
            }
            else if (klaves == 80) { // Šípka DOLE
                cursor++;
                if (cursor >= (int)projekty.size()) cursor = 0;
            }
            else if (klaves == 83) { // DEL — vymazať celý projekt
                std::cout << "\n" << CERVENA << "Delete this project? [Y / N]: " << RESET;
                int confirm = _getch();
                if (confirm == 'y' || confirm == 'Y') {
                    projekty.erase(projekty.begin() + cursor);
                    if (cursor >= (int)projekty.size() && cursor > 0) cursor--;
                    ulozProjektyDoSuboru(projekty);
                }
            }
        }
        else if ((klaves == 'w' || klaves == 'W') && !projekty.empty() && cursor > 0) { // W — presun projekt hore
            std::swap(projekty[cursor], projekty[cursor - 1]);
            cursor--;
            ulozProjektyDoSuboru(projekty);
        }
        else if ((klaves == 'e' || klaves == 'E') && !projekty.empty() && cursor < (int)projekty.size() - 1) { // E — presun projekt dole
            std::swap(projekty[cursor], projekty[cursor + 1]);
            cursor++;
            ulozProjektyDoSuboru(projekty);
        }
        else if (klaves == 'a' || klaves == 'A') { // A — pridať nový projekt
            system("cls");
            std::cout << ZLTA << "Project name: " << RESET;
            std::string nazov;
            std::getline(std::cin, nazov);
            if (!nazov.empty()) {
                Projekt novyProjekt;
                novyProjekt.nazov = nazov;
                projekty.push_back(novyProjekt);
                ulozProjektyDoSuboru(projekty);
                cursor = (int)projekty.size() - 1;
                spravujProjekt(projekty.back(), projekty);
            }
        }
        else if (klaves == 13 && !projekty.empty()) { // Enter — otvoriť projekt
            spravujProjekt(projekty[cursor], projekty);
        }
        else if (klaves == 27 || klaves == 8) { // ESC — späť do menu
            break;
        }
    }
}


// Zmena master hesla — overi stare heslo, vytvori novy salt+kluc, znovu zasifruie data
void zmenHeslo(std::vector<std::string>& ulohy, std::vector<Projekt>& projekty) {
    const std::string authSubor = "auth.dat";

    // Nacitaj aktualny salt pre overenie stareho hesla
    std::vector<uint8_t> salt(16, 0);
    std::vector<uint8_t> ulozenaHash(32, 0);
    std::ifstream fin(authSubor, std::ios::binary);
    if (!fin.is_open()) return;
    fin.read((char*)salt.data(), 16);
    fin.read((char*)ulozenaHash.data(), 32);
    fin.close();

    system("cls");
    std::cout << "\n" << ZLTA << "  Change master password\n\n" << RESET;

    // Overenie stareho hesla
    std::cout << ZLTA << "  Current password: " << RESET;
    std::string stare = citajHesloSkryte();
    if (stare.empty()) return;

    std::vector<uint8_t> staryKandidatKluc = pbkdf2(stare, salt);
    std::string staryKlucStr(staryKandidatKluc.begin(), staryKandidatKluc.end());
    if (sha256(staryKlucStr) != ulozenaHash) {
        std::cout << CERVENA << "  Wrong password.\n" << RESET;
        Sleep(1500); return;
    }

    // Nove heslo
    std::cout << ZLTA << "  New password: " << RESET;
    std::string nove = citajHesloSkryte();
    if (nove.empty()) return;

    std::cout << ZLTA << "  Confirm new password: " << RESET;
    std::string nove2 = citajHesloSkryte();
    if (nove != nove2) {
        std::cout << CERVENA << "  Passwords do not match.\n" << RESET;
        Sleep(1500); return;
    }

    // Novy salt + kluc
    std::vector<uint8_t> novySalt(16);
    BCryptGenRandom(NULL, novySalt.data(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    std::vector<uint8_t> novyKluc = pbkdf2(nove, novySalt);

    // Prepni globalny kluc a znovu zasifruie vsetky data
    KLUC = novyKluc;
    ulozDoSuboru(ulohy);
    ulozProjektyDoSuboru(projekty);

    // Aktualizuj auth.dat
    std::string novyKlucStr(novyKluc.begin(), novyKluc.end());
    std::vector<uint8_t> novyHash = sha256(novyKlucStr);
    std::ofstream fout(authSubor, std::ios::binary);
    fout.write((char*)novySalt.data(), 16);
    fout.write((char*)novyHash.data(), 32);

    std::cout << ZLTA << "\n  Password changed successfully. Press any key...\n" << RESET;
    _getch();
}



// =============================================================================
// VSTUPNY BOD
// =============================================================================

int main() {
    // Zapnutie ANSI farieb pre Windows CMD
    #ifdef _WIN32
    system("X_X 2>nul"); // Hack pre aktiváciu ANSI v starších verziách CMD
    SetConsoleOutputCP(65001); // UTF-8 code page — potrebné pre box-drawing znaky v logu
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= 0x0004; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
            SetConsoleMode(hOut, dwMode);
        }
    }
    #endif

    if (!inicializujSifrovanie()) return 0;

    std::vector<std::string> ulohy    = nacitajZoSuboru();
    std::vector<Projekt>     projekty = nacitajProjektyZoSuboru();

    int indexVolby = 0;   // Aktuálne vysvietená možnosť (0–2)
    bool beziProgram = true;

    while (beziProgram) {
        system("cls");

        // --- Vykreslenie menu ---
        std::cout << "\n";
        tlacLogo(true);
        std::cout << std::endl;

        if (indexVolby == 0)
            std::cout << REVERZ_ZLTA << " > 1. Tasks < " << RESET << std::endl;
        else
            std::cout << ZLTA << "   1. Tasks   " << RESET << std::endl;

        if (indexVolby == 1)
            std::cout << REVERZ_ZLTA << " > 2. Projects < " << RESET << std::endl;
        else
            std::cout << ZLTA << "   2. Projects   " << RESET << std::endl;

        if (indexVolby == 2)
            std::cout << REVERZ_CERVENA << " > 3. Exit < " << RESET << std::endl;
        else
            std::cout << CERVENA << "   3. Exit   " << RESET << std::endl;

        std::cout << DARK << "\n[UP/DOWN = navigate]  [ENTER = confirm]  [C = change password]" << RESET;

        // --- Čítanie klávesového vstupu ---
        // Šípky posielajú dva bajty: prvý je 224, druhý určuje smer (72 = hore, 80 = dole)
        int klaves = _getch();

        if (klaves == 0 || klaves == 224) {
            klaves = _getch();
            if (klaves == 72) { // Šípka HORE
                indexVolby--;
                if (indexVolby < 0) indexVolby = 2;
            }
            else if (klaves == 80) { // Šípka DOLE
                indexVolby++;
                if (indexVolby > 2) indexVolby = 0;
            }
        }
        else if (klaves == 'c' || klaves == 'C') { // C — zmena master hesla
            zmenHeslo(ulohy, projekty);
        }
        else if (klaves == 13) { // Enter

            // --- Akcie menu ---
            if (indexVolby == 0) { // Zobraziť / spravovať úlohy
                spravujUlohy(ulohy);
            }
            else if (indexVolby == 1) { // Zobraziť / spravovať projekty
                spravujProjekty(projekty);
            }
            else if (indexVolby == 2) { // Koniec
                system("cls");
                std::cout << CERVENA << "The app is closing. Take care and have a nice day :)\n" << RESET << "\n";
                tlacLogo(false);
                std::cout << DARK << "\ndeveloped by shapeusto.com\n\n" << RESET;
                beziProgram = false;
            }
        }
    }

    return 0;
}
