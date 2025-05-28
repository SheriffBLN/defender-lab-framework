import sys
from defender_lab import main as defender_lab_main
import generate_matrix_from_apt as apt_matrix

def print_banner():
    banner = r'''
    ╔═════════════════════════════════════════════════════╗
    ║           🛡️  Defender Lab Framework  🛡️            ║
    ╚═════════════════════════════════════════════════════╝
    '''
    print(banner)

def main_menu():
    print_banner()
    print("=== Wybierz tryb pracy ===")
    print("1) Tryby klasyczne: SingleTechnique / APT Group / Update")
    print("2) Automatyczne generowanie macierzy dla grupy APT (STIX)")
    print("0) Wyjście")
    while True:
        try:
            mode = int(input("Wybierz tryb (1/2/0): "))
            if mode in [0,1,2]:
                return mode
        except ValueError:
            pass
        print("Podaj poprawną wartość (1/2/0)")

def apt_matrix_menu():
    print("\n[2] Automatyczne generowanie macierzy APT (STIX)")
    print("Jak chcesz wybierać grupę?")
    print("1) Klasyczny wybór (ID lub nazwa, bez aliasów)")
    print("2) Z aliasami na żądanie ([A] podczas wyboru)")
    print("0) Powrót")
    while True:
        try:
            opt = int(input("Wybierz opcję (1/2/0): "))
            if opt in [0,1,2]:
                return opt
        except ValueError:
            pass
        print("Podaj poprawną wartość (1/2/0)")

def run_apt_matrix(mode):
    STIX_PATH = "tools/helpers/enterprise-attack.json"
    if mode == 1:
        group_entry = apt_matrix.pick_group(STIX_PATH)
    elif mode == 2:
        group_entry = apt_matrix.pick_group_with_alias_option(STIX_PATH)
    else:
        print("Powrót do głównego menu.")
        return
    if not group_entry:
        print("Anulowano wybór grupy.")
        return
    apt_matrix.main(group_entry=group_entry)  # UWAGA: zobacz poniżej wyjaśnienie!

def main():
    while True:
        mode = main_menu()
        if mode == 1:
            defender_lab_main()
        elif mode == 2:
            submode = apt_matrix_menu()
            if submode == 0:
                continue
            run_apt_matrix(submode)
        elif mode == 0:
            print("Do zobaczenia!")
            sys.exit(0)

if __name__ == "__main__":
    main()
