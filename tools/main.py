import sys

from tools.defender_lab import main as defender_lab_main
from tools.generate_matrix_from_apt import main as apt_matrix_main
from tools.generate_global_coverage import main as global_coverage_main
from tools.generate_matrix_from_alert_evidence import main as alert_evidence_main
from tools.generate_full_navigator import main as full_navigator_main  # <--- NOWE

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
    print("3) Global Coverage (ostatnie 30 dni, MITRE Layer + markdown)")
    print("4) AlertEvidence Matrix (per RemoteIP/Host/User/Application)")
    print("5) Zbiorczy eksport do MITRE NAVIGATOR (dla wszystkich status.csv)")
    print("0) Wyjście")
    while True:
        try:
            mode = int(input("Wybierz tryb (1/2/3/4/5/0): "))
            if mode in [0,1,2,3,4,5]:
                return mode
        except ValueError:
            pass
        print("Podaj poprawną wartość (0/1/2/3/4/5)")

def main():
    while True:
        mode = main_menu()
        if mode == 1:
            defender_lab_main()
        elif mode == 2:
            apt_matrix_main()
        elif mode == 3:
            global_coverage_main()
        elif mode == 4:
            alert_evidence_main()
        elif mode == 5:
            full_navigator_main()
        elif mode == 0:
            print("Do zobaczenia!")
            sys.exit(0)

if __name__ == "__main__":
    main()
