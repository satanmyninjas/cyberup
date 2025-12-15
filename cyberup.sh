#!/bin/bash

VERSION=2.9
YEAR=$(date +%Y)

LOG_ERRORS=false
LOG_FILE="$HOME/cyberup-error.log"

## ----------------------------------------------------------------------------
## NAME
##     PACMAN_FLAGS - default pacman installation flags.
##     YAY_FLAGS - default yay installation flags for AUR packages.
##
## SYNOPSIS
##     export PACMAN_FLAGS="flags..."
##     export YAY_FLAGS="flags..."
##
## DESCRIPTION
##     Defines default flags used by pacman for all package installations.
##
##     --needed       Skip reinstalling up-to-date packages.
##     --color=auto   Enable color output if supported.
##
##     Defines default flags used by yay (AUR helper) for installing packages.
##
##     --needed       Skip reinstalling up-to-date packages.
##     --batchinstall Install all packages in one go to improve speed.
##     --removemake   Remove unneeded make dependencies after build.
##     --cleanafter   Auto-clean build cache after install.
##     --color=auto   Enable color output if supported.
##     --pgpfetch     Auto-fetch missing package signing keys (PGP).
## ----------------------------------------------------------------------------
export PACMAN_FLAGS="--needed --color=auto"
export YAY_FLAGS="--needed --batchinstall --removemake --cleanafter --color=auto --pgpfetch"

## ----------------------------------------------------------------------------
## NAME
##     show_usage - display program usage instructions.
##
## SYNOPSIS
##     show_usage
##
## DESCRIPTION
##     Outputs the help page, usage syntax, options, features,
##     and program information for the cyberup script.
##
## AUTHOR
##     Written by SATANMYNINJAS [DEFCON201] [nyc2600]
## ----------------------------------------------------------------------------
show_usage() {
    cat << EOF

NAME
    show_usage - display program usage instructions.

SYNOPSIS
    cyberup [OPTION]

DESCRIPTION
    cyberup automates the setup of an Arch Linux cybersecurity,
    ethical hacking, and digital forensics workstation.

OPTIONS
    --install[=PATH]
        Install cyberup system-wide (default: /usr/local/bin).

    --update
        Download and replace cyberup with the latest version.

    --log-errors
        Enable logging of warnings and errors to \$HOME/cyberup-error.log.

    --help
        Display this help message and exit.

FEATURES
    - Installs categorized tools (core, dev, pentest, forensics, etc).
    - Fetches tools from Arch repos, BlackArch, and the AUR.
    - Optionally refreshes pacman mirrors based on your region.
    - Automatically updates pacman keyring and AUR PGP keys.
    - Generates manpage and installs to /usr/share/man/man1.
    - Optional error logging with --log-errors flag.

EXAMPLES
    ./cyberup.sh --help
    ./cyberup.sh --install
    ./cyberup.sh --log-errors
    ./cyberup.sh --update

AUTHOR
    Written by SATANMYNINJAS

LICENSE
    MIT License

REPOSITORY
    https://github.com/satanmyninjas/cyberup/cyberup.sh

EOF
}

## ----------------------------------------------------------------------------
## NAME
##     log_error - append warnings and error messages to logfile.
##
## SYNOPSIS
##     log_error "message"
##
## DESCRIPTION
##     If error logging is enabled, appends warnings to the log file
##     at \$HOME/cyberup-error.log with a timestamp. Always echoes
##     to stdout regardless.
##
## OPTIONS
##     "message"
##         Message string to log.
##
## AUTHOR
##     Written by SATANMYNINJAS [DEFCON201] [nyc2600]
## ----------------------------------------------------------------------------
log_error() {
    local msg="$1"
    echo "[ WARN ] $msg"
    if [[ "$LOG_ERRORS" == true ]]; then
        echo "$(date +'%Y-%m-%d %H:%M:%S') [ WARN ] $msg" >> "$LOG_FILE"
    fi
}

## ----------------------------------------------------------------------------
## NAME
##     update_cyberup - download and replace cyberup with the latest version.
##
## SYNOPSIS
##     update_cyberup
##
## DESCRIPTION
##     Downloads the latest cyberup script from the GitHub repository
##     and overwrites the local copy. Sets execute permissions.
##
## AUTHOR
##     Written by SATANMYNINJAS [DEFCON201] [nyc2600]
## ----------------------------------------------------------------------------
update_cyberup() {
    echo "[ BUSY ] Checking for cyberup script updates..."
    curl -s -o "$HOME/cyberup.sh" https://raw.githubusercontent.com/satanmyninjas/cyberup/cyberup.sh
    chmod +x "$HOME/cyberup.sh"
    echo "[ :3 ] cyberup updated! Run it with:"
    echo "bash ~/cyberup.sh"
    exit 0
}

## ----------------------------------------------------------------------------
## Function: generate_manpage
## Description:
##     Outputs a formatted manpage for cyberup in roff/groff format.
## ----------------------------------------------------------------------------
generate_manpage() {
cat << 'EOF'
.TH CYBERUP 1 "$YEAR" "v$VERSION" "Cybersecurity Workstation Setup"

.SH NAME
cyberup \- Arch Linux Cybersecurity Workstation Installer

.SH SYNOPSIS
.B cyberup
[\fIOPTION\fR]

.SH DESCRIPTION
cyberup automates the installation of a fully equipped Arch Linux workstation for cybersecurity, forensics, and ethical hacking.

.SH OPTIONS
.TP
\fB--install[=PATH]\fR
Install this script system-wide (default: /usr/local/bin).

.TP
\fB--update\fR
Download and replace the current script with the latest version.

.TP
\fB--log-errors\fR
Enable error/warning logging to \$HOME/cyberup-error.log.

.TP
\fB--help\fR
Display usage help and exit.

.SH FEATURES
- Installs categorized tools (core, dev, pentest, forensics, etc)
- Installs AUR packages using yay
- Auto-refreshes pacman keys and mirrors
- Region-optimized mirror updates
- Error logging support

.SH AUTHOR
Written by SATANMYNINJAS
GITHUB REPO: https://github.com/satanmyninjas/cyberup

.SH LICENSE
MIT License.

.SH SEE ALSO
pacman(8), yay(1), reflector(1)
EOF
}

## ----------------------------------------------------------------------------
## NAME
##     check_yay - verify yay is installed and usable.
##
## SYNOPSIS
##     check_yay
##
## DESCRIPTION
##     Checks for yay (AUR helper) availability in the system \$PATH.
##     Falls back to /tmp/yay if available. Logs errors and exits if not found.
##
## AUTHOR
##     Written by SATANMYNINJAS [DEFCON201] [nyc2600]
## ----------------------------------------------------------------------------
check_yay() {
    if command -v yay >/dev/null 2>&1; then
        echo "[ :3 ] yay is already installed on the system."
        YAY_CMD="yay"
    else
        log_error "[ :( ] yay is not installed."
        read -p "[ ? ] Do you want to run yay from /tmp (if available)? [y/N] " choice
        case "$choice" in
            y|Y )
                if [ -x "/tmp/yay" ]; then
                    echo -e "[ BUSY ] Using yay from /tmp."
                    YAY_CMD="/tmp/yay"
                else
                    log_error "[ :( ] yay not found in /tmp either. Please install yay manually first."
                    exit 1
                fi
                ;;
            * )
                echo "[ :( ] Aborting. Please install yay first."
                exit 1
                ;;
        esac
    fi
}

## ----------------------------------------------------------------------------
## NAME
##     install_blackarch_keyring - add BlackArch repository and keys.
##
## SYNOPSIS
##     install_blackarch_keyring
##
## DESCRIPTION
##     Downloads and runs BlackArch's strap.sh to configure the keyring
##     and repository. Enables multilib support. Refreshes pacman database.
##
## AUTHOR
##     Written by SATANMYNINJAS [DEFCON201] [nyc2600]
## ----------------------------------------------------------------------------
install_blackarch_keyring() {
    echo "[ BUSY ] Setting up BlackArch keyring and downloading bootstrap..."
    curl -O https://blackarch.org/strap.sh

    echo "[ BUSY ] Adding execute permissions to strap.sh file..."
    chmod +x strap.sh
    sudo ./strap.sh

    echo "[ BUSY ] Enabling multilib repository..."
    sudo sed -i '/\[multilib\]/,/Include/s/^#//' /etc/pacman.conf

    echo "[ BUSY ] Updating package databases..."
    sudo pacman -Syu $PACMAN_FLAGS

    echo "[ :3 ] BlackArch keyring setup complete!"
    echo "[ BUSY ] Cleaning up and removing strap.sh..."
    rm strap.sh
}

## ----------------------------------------------------------------------------
## NAME
##     install_ethical_hacking_environment - install full cyber workstation.
##
## SYNOPSIS
##     install_ethical_hacking_environment
##
## DESCRIPTION
##     Installs categorized tools for cybersecurity, reverse engineering,
##     and forensics from official Arch repositories, BlackArch, and AUR.
##     Refreshes mirrorlist based on detected country. Updates keys and
##     package databases. Optionally logs warnings/errors to file.
##
## AUTHOR
##     Written by SATANMYNINJAS [DEFCON201] [nyc2600]
## ----------------------------------------------------------------------------

install_ethical_hacking_environment() {
    echo "[ BUSY ] Installing ethical hacking environment..."
    echo "[ (0_o\") ] You might wanna grab a coffee. This can take a bit..."

    ESSENTIAL_CORE=(
    	linux-lts linux-lts-headers grub-btrfs timeshift os-prober archlinux-keyring networkmanager network-manager-applet fail2ban lynis clamav clamtk smartmontools nvme-cli ethtool iw rfkill pciutils inxi dmidecode pacman-contrib pkgfile man-db man parallel
    )

    BASE_PACKAGES=(
        base-devel git wget curl unzip zip p7zip htop btop tmux fish fzf fd ripgrep btop binutils nasm testdisk iputils traceroute bind reflector screen
    )

    DEV_TOOLS=(
        vim gvim gcc clang gdb lldb cmake make valgrind strace ltrace python python-pip ipython jupyter-notebook python-virtualenv jdk-openjdk maven gradle go rustup rust nodejs npm yarn shellcheck ruby neovim github-cli
    )

    CYBERSEC_TOOLS=(
        metasploit nmap wireshark-qt john hydra sqlmap nikto aircrack-ng impacket whois
    )

    REVERSE_TOOLS=(
        ghidra radare2 binwalk cutter gdb bless capstone lsof sysdig strace hexedit ltrace
    )

    FORENSICS_TOOLS=(
        sleuthkit testdisk foremost btrfs-progs exfat-utils volatility3 ddrescue tcpdump dsniff
    )

    ETHICAL_HACKING_TOOLS=(
        hashcat kismet wifite reaver cowpatty mitmproxy bettercap bully wifite aircrack-ng chntpw
    )

    NETWORKING_TOOLS=(
        traceroute iperf3 tcpdump openssh tmate bind openvpn wireguard-tools
    )

    VIRTUALIZATION_TOOLS=(
        qemu-full libvirt virt-manager docker docker-compose virtualbox virtualbox-host-modules-arch edk2-ovmf
    )

    SECURITY_PRIVACY=(
        ufw gufw veracrypt gnupg keepassxc tor torbrowser-launcher rkhunter macchanger
    )

    NOTETAKING_REPORT_TOOLS=(
        libreoffice-fresh okular zathura zathura-pdf-poppler obsidian cherrytree exploitdb rnote
    )

    EXTRAS=(
        ranger nnn thunar imagemagick perl-image-exiftool poppler pdftk qpdf telegram-desktop
    )

    FONTS_THEMES=(
        ttf-jetbrains-mono ttf-fira-code ttf-roboto-mono papirus-icon-theme noto-fonts noto-fonts-emoji noto-fonts-cjk
    )

    AUR_PACKAGES=(
        downgrade gophish mullvad-vpn sddm-lain-wired-theme discord_arch_electron wordlists social-engineer-toolkit spiderfoot burpsuite recon-ng dnsprobe chkrootkit autopsy gobuster zenmap responder retdec extundelete guymager crunch sherlock-git phoneinfoga-bin osintgram dcfldd simplescreenrecorder binaryninja-free zoom otf-monocraft mkinitcpio-firmware powershell beef-xss ccrypt chirp-next code-translucent cutecom dumpsterdiver-git exploitdb-bin-sploits-git exploitdb-papers-git extundelete fatcat ferret-sidejack gr-osmosdr-git gss-ntlmssp gtkhash hamster-sidejack havoc hubble-bin hyperion.ng-git instaloader joplin libfreefare-git merlin miredo nmapsi4 ophcrack owl peass-ng pocsuite3 powershell powershell-empire python-ldapdomaindump readpe rephrase robotstxt sendemail sliver sparrow-wifi-git spire-bin swaks tightvnc tnscmd10g vboot-utils vopono waybackpy whatmask wifipumpkin3-git wordlists xmount zerofree whatweb seclists vagrant
    )

    KALI_TOOLS_EXTRACTED=(
        7zip arp-scan arpwatch atftp axel bettercap binwalk bluez bully cabextract cadaver capstone cherrytree chntpw cilium-cli clamav cosign cowpatty curlftpfs darkstat dbeaver ddrescue dos2unix dsniff eksctl ettercap expect exploitdb ext3grep fcrackzip findomain flashrom foremost fping freeradius ghidra git gitleaks gnu-netcat gnuradio gpart gparted gptfdisk gsocket hackrf hashcat hashcat-utils hcxtools hurl hydra impacket inspectrum libpst lynis masscan mc nasm nbtscan ncrack netscanner openvpn p0f pdfcrack pixiewps python-pipx python-virtualenv radare2 rarcrack routersploit ruby-rake seclists skipfish smbclient smtp-user-enum snmpcheck splint sqlite sqlmap ssldump sslscan steghide tcpdump testdisk thc-ipv6 tor traceroute unicornscan wafw00f wireshark-qt wpscan zaproxy zim zsh-autosuggestions zsh-syntax-highlighting lvm2 nfs-utils 0trace above aesfix aeskeyfind afflib airgeddon altdns amap amass apache-users arjun armitage asleap assetfinder autopsy autorecon bed bettercap-ui bing-ip2hosts bloodhound bloodyad blue-hydra bluelog blueranger bluesnarfer braa bruteforce-luks bruteforce-salted-openssl bruteforce-wallet brutespray btscanner bulk-extractor burpsuite bytecode-viewer certgraph certi cewl chainsaw chisel cisco-torch cookie-cadger crackmapexec crowbar cuckoo cutter darkdump dcfldd det dirb dirbuster dnsenum dnsmap dnsrecon dnstracer doona eapmd5pass edb-debugger enum4linux-ng enumiax fern-wifi-cracker fierce flawfinder fs-nyarl ghost-phisher goofile gospider gqrx hash-identifier haystack hexinject httprint intersect inurlbr johnny killerbee kismet legion linux-exploit-suggester mac-robber magicrescue maltego maryam maskprocessor massdns mdbtools memdump metagoofil mfcuk mimikatz missidentify mitm6 multimac myrescue naabu netdiscover netexec netmask netsed nextnet nishang nuclei o-saft ohrwurm ollydbg onesixtyone oscanner osrframework outguess pack pacu padbuster paros parsero pasco passdetective patator payloadsallthethings pdf-parser pdfid perl-cisco-copyconfig phishery photon pip3line pkt2flow plecost polenum powerfuzzer proxmark3 pwnat pyrit rainbowcrack rcracki_mt rsmangler rtpbreak sakis3g set shellnoob siparmyknife skiptracer sn0int sparta spooftooph sqlninja sqlsus sslcaudit sslsplit sublist3r termineter thc-pptp-bruter tlssled twofi u3-pwn unicornscan vega veil villain vinetto vlan voiphopper wafw00f wapiti wce webacoo webscarab webshells weevely wfuzz whatweb wifi-honey wifiphisher wig windows-binaries windows-privesc-check winregfs xplico
    )

    echo "[ BUSY ] Updating keyring and databases first..."
    sudo pacman -Syy $PACMAN_FLAGS archlinux-keyring


    if ! command -v reflector >/dev/null 2>&1; then
        echo "[ :( ] Reflector not found. Installing..."
        sudo pacman -S $PACMAN_FLAGS reflector
    fi

    # Prompt to refresh Arch mirrors using reflector.
    read -rp "[ ? ] Do you want to refresh your Arch mirrors with the fastest mirrors for your region? [y/N] " refresh_mirrors

    if [[ "$refresh_mirrors" =~ ^[Yy]$ ]]; then
        echo "[ BUSY ] Determining your country for optimal mirrors..."

        # Auto-detect country code using ipinfo.io or fallback to US
        user_country=$(curl -s https://ipinfo.io/country || echo "US")
        user_country=${user_country//[$'\t\r\n']}  # Trim whitespace

        echo "[ :3 ] Detected country: $user_country"

        echo "[ BUSY ] Backing up current mirrorlist..."
        sudo cp /etc/pacman.d/mirrorlist /etc/pacman.d/mirrorlist.bak.$(date +%Y%m%d)

        echo "[ BUSY ] Sorting fresh Arch mirrors..."
        sudo reflector -p https -c "$user_country" --sort rate --verbose --save /etc/pacman.d/mirrorlist

        echo "[ :3 ] Done sorting mirrors for region: $user_country"
    else
        echo "[ BUSY ] Skipping mirrorlist refresh..."
    fi

    # Install necessary packages.
    echo "[ BUSY ] Installing a fuckload of packages..."

    # Install all categorized packages (inline for clarity)
    sudo pacman -Syu $PACMAN_FLAGS \
        "${ESSENTIAL_CORE[@]}" \
        "${BASE_PACKAGES[@]}" \
        "${DEV_TOOLS[@]}" \
        "${CYBERSEC_TOOLS[@]}" \
        "${REVERSE_TOOLS[@]}" \
        "${FORENSICS_TOOLS[@]}" \
        "${ETHICAL_HACKING_TOOLS[@]}" \
        "${NETWORKING_TOOLS[@]}" \
        "${VIRTUALIZATION_TOOLS[@]}" \
        "${SECURITY_PRIVACY[@]}" \
        "${NOTETAKING_REPORT_TOOLS[@]}" \
        "${EXTRAS[@]}" \
        "${FONTS_THEMES[@]}" \
        "${KALI_TOOLS_EXTRACTED[@]}"
    echo "[ :3 ] Holy fuck it finished."

    # Check yay availability.
    check_yay

    # Begin package installation and update logic using $YAY_CMD.
    echo "[ BUSY ] Installing AUR packages..."
    $YAY_CMD -Syyu $YAY_FLAGS "${AUR_PACKAGES[@]}"
    echo "[ :3 ] Done installing all AUR packages."

    echo "[ BUSY ] Updating system..."
    sudo pacman -Syu
    echo "[ :3 ] Done updating system."

    echo "[ :3c ] Ethical hacking environment setup complete!"
}

## ----------------------------------------------------------------------------
## NAME
##     display_ASCII_header - print program banner.
##
## SYNOPSIS
##     display_ASCII_header
##
## DESCRIPTION
##     Outputs the cyberup banner, version number, license, and
##     project purpose to the terminal.
##
## AUTHOR
##     Written by SATANMYNINJAS [DEFCON201] [nyc2600]
## ----------------------------------------------------------------------------
display_ASCII_header() {

    echo -e "\n\n"
    echo "  ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░  "
    echo " ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ "
    echo " ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ "
    echo " ░▒▓█▓▒░       ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░  "
    echo " ░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        "
    echo " ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        "
    echo "  ░▒▓██████▓▒░   ░▒▓█▓▒░   ░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░        "
    echo -e "\n"
    echo -e "                             CYBERUP, v$VERSION, $YEAR                    \n"
    echo -e "                         MIT LICENSE -- by SATANMYNINJAS\n\n"
    echo -e " This script automates the installation of essential tools and utilities for a fully equipped"
    echo -e " cybersecurity, ethical hacking, reverse engineering, and forensics workstation on Arch Linux."
    echo -e " Designed with efficiency and comprehensiveness in mind, it ensures your system is ready for"
    echo -e " coding, penetration testing, and forensic investigations with a single execution.\n"
}

## ----------------------------------------------------------------------------
## NAME
##     print_hacker_quote - display a random hacker quote.
##
## SYNOPSIS
##     print_hacker_quote
##
## DESCRIPTION
##     Outputs a randomly selected quote from hacker history, culture,
##     or cybersecurity folklore. Used for fun and vibe.
##
## AUTHOR
##     Written by SATANMYNINJAS [DEFCON201] [nyc2600]
## ----------------------------------------------------------------------------
print_hacker_quote() {
    local quotes=(
        " <theplague> there is no right and wrong. there's only fun and boring."
        " <ZeroCool> mess with the best, die like the rest."
        " <CerealKiller> FYI man, you could sit at home, do absolutely nothing, and your name goes through like 17 computers a day."
        " <R4Z0R> remember, hacking is more than just a crime. it's a survival trait."
        " <L07DN1K0N> you're in the butter zone now, baby."
        " <4C1DBU7N> never send a boy to do a woman's job."
        " <C3734LK1LL37> spandex: it's a privilege, not a right."
        " <Z370C001> HACK THE PLANET!!!"
        " <C3734K1LL37> we have no names, man. no names. we are nameless!"
        " <linus_t0rv41d5> talk is cheap. show me the code."
        " <edsgar_d1kstr4> testing shows the presence, not the absence of bugs."
        " <WH1T3R0S3> every hacker has her fixation. you hack people. i hack time."
        " <WH1T3R0S3> the concept of waiting bewilders me. there are always deadlines. there are always ticking clocks."
        " <samsepi0l> ...there are some people out there, and it doesn't happen a lot. it's rare. but they refuse to let you hate them. in fact, they care about you in spite of it. and the really special ones, they're relentless at it. doesn't matter what you do to them. they take it and care about you anyway. they don't abandon you, no matter how many reasons you give them. no matter how much you're practically begging them to leave. and you wanna know why? because they feel something for me that i can't -- they love me. and for all the pain i've been through, that heals me. maybe not instantly. maybe not even for a long time, but it heals."
        " <samsepi0l> what if changing the world was just about being here, by showing up no matter how many times we get told we don’t belong, by staying true even when we’re shamed into being false, by believing in ourselves even when we’re told we’re too different? and if we all held on to that, if we refuse to budge and fall in line, if we stood our ground for long enough, just maybe...the world can’t help but change around us."
        " <mr_r0b0t> exciting times in the world...exciting times."
        " <L30N> existence could be beautiful,  or it could be ugly. but that's on you."
        " <samsepi0l> a bug is never just a mistake. it represents something bigger. an error of thinking that makes you who you are."
        " <mr_r0b0t> are you a one or a zero? that's the question you have to ask yourself. are you a yes or a no? are you going to act or not?"
        " <g30rg3_c4rr3t3> first learn computer science and all the theory. next develop a programming style. then forget all that and just hack."
        " <TH3_M3NT0R> yes, i am a criminal.  my crime is that of curiosity.  my crime is that of judging people by what they say and think, not what they look like. my crime is that of outsmarting you, something that you will never forgive me for."
        " <TH3_M3NT0R> you may stop this indivdual, but you can't stop us all...after all, we're all alike."
    )
    local count=${#quotes[@]}
    local random_index=$(( RANDOM % count ))
    echo -e "\n${quotes[$random_index]}\n"
}

# Check if script runs as root; exit if true.
if [ "$EUID" -eq 0 ]; then
    echo -e "[ :( ] Do not run this script as root. Please run as an unprivileged user. Exiting shell script...\n"
    exit 1
fi

# Handle local install logic and generates manpage.
if [[ "$1" == "--install" || "$1" == --install=* ]]; then
    INSTALL_DIR="/usr/local/bin"
    MANPAGE_DIR="/usr/share/man/man1"
    SCRIPT_NAME="cyberup"

    if [[ "$1" == --install=* ]]; then
        INSTALL_DIR="${1#--install=}"
    fi

    echo "[ BUSY ] Installing to $INSTALL_DIR/$SCRIPT_NAME ..."
    sudo cp "$0" "$INSTALL_DIR/$SCRIPT_NAME"
    sudo chmod +x "$INSTALL_DIR/$SCRIPT_NAME"

    echo "[ BUSY ] Installing manpage to $MANPAGE_DIR ..."
    generate_manpage | sudo tee "$MANPAGE_DIR/cyberup.1" > /dev/null
    sudo gzip -f "$MANPAGE_DIR/cyberup.1"

    echo "[ BUSY ] Updating man database ..."
    sudo mandb

    echo "[ :3c ] Installed successfully. You can now run 'cyberup' or 'man cyberup'"
    echo "[ ! ] If you updated this script, be sure to run ./cyberup --install to have the latest version be available system wide. Exiting cleanly...\n"
    exit 0
fi

# Pulls from GitHub repo to update script.
if [[ "$1" == "--update" ]]; then
    update_cyberup
fi

# Shows help message.
if [[ "$1" == "--help" ]] then
    show_usage
fi

# Logs errors to a file.
if [[ "$1" == "--log-errors" ]]; then
    LOG_ERRORS=true
    echo "[ :3 ] Logging enabled! Errors and warnings will be saved to: $LOG_FILE"
    : > "$LOG_FILE"  # Wipe previous log
fi

# Main menu.
while true; do

    clear

    display_ASCII_header
    echo     "           CYBERUP Arch Linux Workstation Setup Script, v$VERSION"
    echo     "  ==========================================================================="
    echo     "  [1] Install BlackArch keyring only."
    echo     "  [2] Install ethical hacking environment only."
    echo     "  [3] Install both BlackArch keyring and ethical hacking environment. :3c"
    echo     "  [4] Show help page and program usage."
    echo     "  [5] Give me some wisdom!"
    echo     "  [6] Exit program."
    echo -e  "  ===========================================================================\n"
    read -rp "  [ ? ] Choose an option [1-6]: " choice

    case $choice in
        1)
            install_blackarch_keyring
            break
            ;;
        2)
            install_ethical_hacking_environment
            break
            ;;
        3)
            install_blackarch_keyring
            install_ethical_hacking_environment
            break
            ;;
        4)
            show_usage
	    break
            ;;
        5)
            echo "  [ :3 ] Here's some wisdom for today..."
            print_hacker_quote
	    break
            ;;
        6)
            echo -e "\n  [ :3c ] Exiting setup. Goodbye! (=^w^=)/\n"
            exit 0
            ;;
        *)
            echo -e "\n  [ :( ] Invalid choice. Please select a valid option.\n"
            break
            ;;
    esac
done
