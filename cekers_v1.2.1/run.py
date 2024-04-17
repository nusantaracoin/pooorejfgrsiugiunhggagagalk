import sys
import cekkerentanan
import pyfiglet
from termcolor import colored
from colorama import Fore, Style
import webbrowser
import git

def main():
    while True:
        banner_text = "* .CEKERS. *"
        versi_beta = "Beta Version 1.2.1"
        github_info = "admin: https://github.com/nusantaracoin/CEKERS-BY-TRS.git"
        jarak_text = ""
        banner = pyfiglet.figlet_format(banner_text)
        colored_banner = colored(banner, color='green')
        colored_versi = colored(versi_beta, color='green')
        github_print = colored(github_info, color='green')
        jarak_print = colored(jarak_text, color='green')
        print(colored_banner)
        print(colored_versi)
        print(github_print)
        print(jarak_print)

        print_menu()
        pilihan = input(colored("Masukkan pilihan Anda: ", "yellow"))

        if pilihan == "1":
            cekkerentanan.main()
        elif pilihan == "2":
            print("coming soon in versi 1.4 or 1.5 beta")
        elif pilihan == "3":
            cookies = cekkerentanan.read_cookies_from_file()  # Panggil fungsi tanpa argumen
            if cookies:
                print(f"{Fore.YELLOW}Cookies berhasil dibaca:", cookies)
        elif pilihan == "4":
            try:
                repo = git.Repo('.')
                origin = repo.remote(name='origin')
                origin.pull()
                print(f"{Fore.GREEN}Pembaruan berhasil diunduh dari GitHub.")
            except Exception as e:
                print(f"{Fore.RED}Gagal mengunduh pembaruan/belum ada update: {e}")
        elif pilihan == "5":
            link = "https://www.tiktok.com/@trs_info?_t=8lbA7QuaVVo&_r=1"  # Ganti dengan link yang ingin Anda buka
            open_link(link)
        elif pilihan == "0":
            print(f"{Fore.GREEN}Good By *x*")
            sys.exit()
        else:
            print(f"{Fore.RED}Pilihan tidak valid.")

def print_menu():
    print(colored("Pilihan Anda:", "green"))
    print(colored("1. ", "green") + "Run Cekers" f"{Fore.YELLOW} *-*")
    print(colored("2. ", "green") + "Jalankan Program Lain" f"{Fore.YELLOW} [xox]")
    print(colored("3. ", "green") + "Baca Cookies" f"{Fore.YELLOW} ^o^")
    print(colored("4. ", "green") + "Update dari GitHub" f"{Fore.YELLOW} <->")
    print(colored("5. ", "green") + "Follow TikTok mimin" f"{Fore.YELLOW} ^-^")
    print(colored("0. ", "green") + "Keluar dari program" f"{Fore.YELLOW} x-x")

def open_link(url):
    webbrowser.open(url)

if __name__ == "__main__":
    main()
