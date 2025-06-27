#!/usr/bin/env python3
import os
import subprocess
import threading
import shutil
import re
import sys
from pathlib import Path
from colorama import Fore, init

init(autoreset=True)

HEADER = f"""{Fore.GREEN}

╔════════════════════════════╗
║        (⌐■_■) RECON        ║
║       FRAMEWORK v1.0       ║
║    Coded by Ketaxpl0it     ║
╚════════════════════════════╝

{Fore.CYAN}  ~ made by Ketaxpl0it[NEEL] ~

"""
print(HEADER)

tools = {
    "subfinder": "subfinder -d {domain} -silent -o {output}",
    "nmap": "nmap -iL {input} -T4 -oN {output}",
    "dirsearch": "dirsearch -u {url} -e * -o {output}",
    "gau": "gau {domain} > {output}",
    "gf": "cat {input} | gf {pattern} > {output}"
}

def check_dependencies():
    print(f"{Fore.YELLOW}[*] Checking required tools...")
    required = ["subfinder", "httpx", "dirsearch", "gau", "gf", "xargs"]
    missing = [tool for tool in required if not shutil.which(tool)]
    if missing:
        print(f"{Fore.RED}[!] Missing tools: {', '.join(missing)}")
        sys.exit(1)
    print(f"{Fore.GREEN}[✓] All required tools found.")

def run_cmd(cmd):
    print(f"{Fore.BLUE}[+] Running: {cmd}")
    os.system(cmd)

def subfinder(domain, output_dir):
    output = output_dir / "subdomains.txt"
    run_cmd(tools["subfinder"].format(domain=domain, output=output))
    return output

def httpx_bulk(input_file, output_dir):
    output = output_dir / "live.txt"
    if input_file.exists():
        print(f"{Fore.BLUE}[+] Running httpx on all subdomains...")

        # Prepare the list with http:// prefix
        temp_input = output_dir / "httpx_input.tmp"
        with open(input_file) as f_in, open(temp_input, "w") as f_out:
            for line in f_in:
                domain = line.strip()
                if domain:
                    f_out.write(f"http://{domain}\n")

        cmd = f"httpx -l {temp_input} --follow-redirects -silent -status-code > {output}"
        run_cmd(cmd)

        if output.exists() and output.stat().st_size > 0:
            print(f"{Fore.GREEN}[✓] Live domains written to {output}")
            temp_input.unlink()
            return output
        else:
            print(f"{Fore.RED}[!] httpx completed but no live domains found.")
            temp_input.unlink()
    else:
        print(f"{Fore.RED}[!] Input file {input_file} does not exist.")
    return None

def dirsearch_scan(target_url, output_dir):
    if not target_url.startswith("http"):
        return
    file_safe = target_url.replace("://", "_").replace("/", "_")
    output = output_dir / f"dir_{file_safe}.txt"
    run_cmd(tools["dirsearch"].format(url=target_url, output=output))

def gau_links(domain, output_dir):
    output = output_dir / "gau.txt"
    run_cmd(tools["gau"].format(domain=domain, output=output))
    return output if output.exists() else None

def gf_patterns(input_file, pattern, output_dir):
    output = output_dir / f"{pattern}_patterns.txt"
    if input_file and input_file.exists():
        run_cmd(tools["gf"].format(input=input_file, pattern=pattern, output=output))
    else:
        print(f"{Fore.YELLOW}[!] Skipping GF pattern '{pattern}': gau.txt not found.")

def main():
    check_dependencies()
    domain = input(f"{Fore.CYAN}[?] Enter domain: ").strip()
    if not domain:
        print(f"{Fore.RED}[!] No domain provided. Exiting.")
        return

    base_dir = Path(f"./recon/{domain}")
    base_dir.mkdir(parents=True, exist_ok=True)

    print(f"{Fore.YELLOW}[*] Running Subfinder...")
    sub_file = subfinder(domain, base_dir)

    print(f"{Fore.YELLOW}[*] Checking Live Hosts with httpx...")
    live_file = httpx_bulk(sub_file, base_dir)

    print(f"{Fore.YELLOW}[*] Launching directory fuzzing...")
    if live_file and live_file.exists():
        with open(live_file) as f:
            threads = []
            for line in f:
                url = line.strip()
                if url:
                    t = threading.Thread(target=dirsearch_scan, args=(url, base_dir))
                    t.start()
                    threads.append(t)
            for t in threads:
                t.join()
    else:
        print(f"{Fore.RED}[!] Skipping Dirsearch: live.txt not found.")

    print(f"{Fore.YELLOW}[*] Collecting URLs via gau...")
    gau_file = gau_links(domain, base_dir)

    print(f"{Fore.YELLOW}[*] Running gf pattern matching...")
    for pattern in ["xss", "sqli", "lfi", "ssti", "idor"]:
        gf_patterns(gau_file, pattern, base_dir)

    print(f"{Fore.GREEN}[✓] Recon complete. Results saved in: {base_dir.resolve()}")

if __name__ == "__main__":
    main()
