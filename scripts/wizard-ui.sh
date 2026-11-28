# Screens of the setup wizard (whiptail). Sourced by setup-wizard.sh when a terminal is there;
# without whiptail, without a terminal or with AWG31_UI=text the wizard asks plain questions.
# Everything is chosen before the installation starts: then a progress bar runs and the
# command output goes to $WIZ_LOG, shown only when something fails.

WIZ_LANG="${AWG31_LANG:-ru}"
WIZ_LOG="${AWG31_INSTALL_LOG:-/var/log/awg31-install.log}"
WIZ_TTY="${AWG31_TTY:-/dev/tty}"
WIZ_GAUGE_PID=''
WIZ_GAUGE_FIFO=''

# ---------------------------------------------------------------- texts
declare -A T_ru=(
  [backtitle]='AmneziaWG 3.1 Console — установка'
  [lang_title]='Язык / Language' [lang_text]='Язык мастера установки'
  [welcome_title]='Добро пожаловать'
  [welcome]='Мастер поставит VPN AmneziaWG 3.1 (модуль ядра, без Docker) и веб-панель.\n\nСистема: %s\nВнешний интерфейс: %s\nПубличный адрес: %s\n\nСначала вы выберете параметры — ничего не меняется, пока не нажмёте «Установить».\nСтрелки — выбор, Enter — открыть, Esc — назад.'
  [menu_title]='Параметры установки' [menu_text]='Выберите пункт, чтобы изменить его. Значения по умолчанию подходят для большинства серверов.'
  [i_subnet]='Подсеть VPN' [i_port]='UDP-порт VPN' [i_endpoint]='Адрес сервера для клиентов' [i_dns]='DNS для клиентов'
  [i_mode]='Какой трафик через VPN' [i_uplink]='Внешний интерфейс' [i_mtu]='MTU туннеля' [i_panel]='Порт веб-панели'
  [i_client]='Первый клиент' [i_https]='HTTPS для панели' [i_password]='Пароль панели' [i_firewall]='Открыть порт в %s'
  [i_install]='▶ Установить' [i_cancel]='Отмена'
  [subnet_text]='Подсеть, из которой клиенты получают адреса.'
  [subnet_default]='Стандартная 10.77.10.0/24' [subnet_random]='Случайная 10.x.y.0/24 (своя на каждом сервере)' [subnet_custom]='Своя…'
  [subnet_input]='Подсеть в формате CIDR, от /24 до /29, например 10.20.30.0/24'
  [port_text]='UDP-порт, на котором сервер ждёт клиентов (1–65535). Его нужно будет открыть в файрволе провайдера.'
  [port_random]='случайный'
  [endpoint_text]='Публичный IPv4 или доменное имя сервера — оно попадёт в конфигурации клиентов.'
  [dns_text]='DNS-сервер, который получат клиенты.' [dns_custom]='Свой…' [dns_input]='IPv4-адрес DNS-сервера'
  [mode_text]='Что отправлять через VPN.' [mode_full]='Весь IPv4-трафик клиента (рекомендуется)' [mode_split]='Только VPN-подсеть'
  [uplink_text]='Интерфейс, через который клиенты выходят в интернет (NAT).'
  [mtu_text]='MTU туннеля, 576–1420. 1280 подходит почти всегда.'
  [panel_text]='TCP-порт, на котором веб-панель слушает только 127.0.0.1.'
  [client_text]='Имя первого клиента: латиница, цифры, - и _. Пусто — не создавать.'
  [https_text]='Панель всегда слушает только localhost. HTTPS через Nginx можно включить и позже: sudo awg31 nginx.'
  [https_none]='Без HTTPS (доступ через SSH-туннель)' [https_self]='Nginx + самоподписанный сертификат' [https_own]='Nginx + свой сертификат (PEM)'
  [https_host]='Домен или IPv4 для HTTPS (без схемы и порта)' [https_port]='Публичный TCP-порт HTTPS'
  [https_cert]='Путь к сертификату PEM (fullchain)' [https_key]='Путь к приватному ключу PEM'
  [pass_text]='Пароль администратора веб-панели.' [pass_gen]='Сгенерировать (сохранится в файл, виден только root)' [pass_own]='Задать свой…'
  [pass_input]='Пароль, не короче 12 символов' [pass_repeat]='Повторите пароль'
  [pass_short]='Пароль должен быть от 12 до 256 символов.' [pass_mismatch]='Пароли не совпадают.'
  [v_none]='нет' [v_gen]='сгенерировать' [v_own]='свой' [v_yes]='да' [v_no]='нет'
  [fw_text]='Включён %s. Открыть в нём UDP-порт VPN? Без этого клиенты не подключатся.'
  [error_title]='Проверьте параметры'
  [cancel_text]='Выйти без установки?'
  [selinux_text]='SELinux в режиме Enforcing: Nginx нужно разрешение httpd_can_network_connect. Включить его (SELinux остаётся включённым)?'
  [firewalld_text]='Работает firewalld. Для режима «весь трафик» может понадобиться отдельная настройка его политики и NAT. Продолжить?'
  [gauge_title]='Установка · журнал %s'
  [done_title]='Готово'
  [failed]='Установка остановилась. Последние строки журнала %s:'
  [s_deps]='Установка пакетов' [s_module]='Проверка модуля AmneziaWG 3.1' [s_files]='Копирование программы'
  [s_venv]='Python-окружение панели' [s_net]='Сетевые настройки ядра' [s_vpn]='Запуск VPN awg0'
  [s_user]='Пользователь и пароль панели' [s_panel]='Запуск веб-панели' [s_timers]='Службы и расписания'
  [s_nginx]='Nginx и HTTPS' [s_telegram]='Telegram-бот' [s_firewall]='Файрвол' [s_done]='Готово'
)
declare -A T_en=(
  [backtitle]='AmneziaWG 3.1 Console — setup'
  [lang_title]='Язык / Language' [lang_text]='Language of the setup wizard'
  [welcome_title]='Welcome'
  [welcome]='The wizard installs the AmneziaWG 3.1 VPN (kernel module, no Docker) and the web panel.\n\nSystem: %s\nUplink interface: %s\nPublic address: %s\n\nFirst you choose the settings; nothing changes until you press Install.\nArrows choose, Enter opens, Esc goes back.'
  [menu_title]='Installation settings' [menu_text]='Pick an item to change it. The defaults suit most servers.'
  [i_subnet]='VPN subnet' [i_port]='VPN UDP port' [i_endpoint]='Server address for clients' [i_dns]='DNS for clients'
  [i_mode]='Traffic through the VPN' [i_uplink]='Uplink interface' [i_mtu]='Tunnel MTU' [i_panel]='Web panel port'
  [i_client]='First client' [i_https]='HTTPS for the panel' [i_password]='Panel password' [i_firewall]='Open the port in %s'
  [i_install]='▶ Install' [i_cancel]='Cancel'
  [subnet_text]='The subnet clients get their addresses from.'
  [subnet_default]='Standard 10.77.10.0/24' [subnet_random]='Random 10.x.y.0/24 (its own on every server)' [subnet_custom]='Custom…'
  [subnet_input]='Subnet in CIDR notation, /24 to /29, e.g. 10.20.30.0/24'
  [port_text]='UDP port the server listens on (1–65535). Open it in the provider firewall too.'
  [port_random]='random'
  [endpoint_text]='Public IPv4 or domain name of the server; it goes into the client configurations.'
  [dns_text]='DNS server the clients get.' [dns_custom]='Custom…' [dns_input]='IPv4 address of the DNS server'
  [mode_text]='What goes through the VPN.' [mode_full]='All IPv4 traffic of the client (recommended)' [mode_split]='The VPN subnet only'
  [uplink_text]='Interface the clients reach the internet through (NAT).'
  [mtu_text]='Tunnel MTU, 576–1420. 1280 fits nearly always.'
  [panel_text]='TCP port the web panel listens on, on 127.0.0.1 only.'
  [client_text]='Name of the first client: Latin letters, digits, - and _. Empty: none.'
  [https_text]='The panel always listens on localhost only. HTTPS through Nginx can also be set up later: sudo awg31 nginx.'
  [https_none]='No HTTPS (access through an SSH tunnel)' [https_self]='Nginx + self-signed certificate' [https_own]='Nginx + your certificate (PEM)'
  [https_host]='Domain or IPv4 for HTTPS (no scheme, no port)' [https_port]='Public HTTPS TCP port'
  [https_cert]='Path to the PEM certificate (fullchain)' [https_key]='Path to the PEM private key'
  [pass_text]='Password of the web panel administrator.' [pass_gen]='Generate (saved to a file only root can read)' [pass_own]='Set my own…'
  [pass_input]='Password, at least 12 characters' [pass_repeat]='Repeat the password'
  [pass_short]='The password must be 12 to 256 characters long.' [pass_mismatch]='The passwords do not match.'
  [v_none]='none' [v_gen]='generate' [v_own]='own' [v_yes]='yes' [v_no]='no'
  [fw_text]='%s is active. Open the VPN UDP port in it? Without that clients cannot connect.'
  [error_title]='Check the settings'
  [cancel_text]='Leave without installing?'
  [selinux_text]='SELinux is Enforcing: Nginx needs the httpd_can_network_connect permission. Turn it on (SELinux stays on)?'
  [firewalld_text]='firewalld is running. For the full tunnel its policy and NAT may need separate setup. Continue?'
  [gauge_title]='Installing · log %s'
  [done_title]='Done'
  [failed]='The installation stopped. Last lines of %s:'
  [s_deps]='Installing packages' [s_module]='Checking the AmneziaWG 3.1 module' [s_files]='Copying the program'
  [s_venv]='Python environment of the panel' [s_net]='Kernel network settings' [s_vpn]='Starting the awg0 VPN'
  [s_user]='Panel user and password' [s_panel]='Starting the web panel' [s_timers]='Services and schedules'
  [s_nginx]='Nginx and HTTPS' [s_telegram]='Telegram bot' [s_firewall]='Firewall' [s_done]='Done'
)

ui_t() {
    local key="$1"
    if [[ "$WIZ_LANG" == en ]]; then printf '%s' "${T_en[$key]:-$key}"; else printf '%s' "${T_ru[$key]:-$key}"; fi
}

# ---------------------------------------------------------------- whiptail wrappers
# whiptail draws on the terminal and writes the answer to stderr: swap them.
wt() { whiptail --backtitle "$(ui_t backtitle)" "$@" 3>&1 1>&2 2>&3; }
ui_msg() { wt --title "$1" --msgbox "$2" 20 76 || :; }
ui_yesno() { whiptail --backtitle "$(ui_t backtitle)" --title "$1" --yesno "$2" 12 76 3>&1 1>&2 2>&3; }
ui_input() { wt --title "$1" --inputbox "$2" 11 76 "$3"; }
ui_password() { wt --title "$1" --passwordbox "$2" 10 76; }
# ui_choice TITLE TEXT CURRENT TAG LABEL TAG LABEL...: a radio list, CURRENT preselected.
ui_choice() {
    local title="$1" text="$2" current="$3" items=() n=0; shift 3
    while [[ $# -ge 2 ]]; do
        items+=("$1" "$2" "$([[ "$1" == "$current" ]] && echo ON || echo OFF)"); shift 2; n=$((n + 1))
    done
    wt --title "$title" --notags --radiolist "$text" $((n + 9)) 76 "$n" "${items[@]}"
}

# ---------------------------------------------------------------- the screens
ui_language() {
    local choice
    choice="$(wt --title "$(ui_t lang_title)" --notags --menu "$(ui_t lang_text)" 12 60 2 ru 'Русский' en 'English')" || exit 1
    WIZ_LANG="$choice"
}

ui_welcome() {
    local text
    # shellcheck disable=SC2059
    printf -v text "$(ui_t welcome)" "${AWG31_OS_PRETTY:-Linux}" "${DEFAULT_UPLINK:-?}" "${DEFAULT_IP:-?}"
    wt --title "$(ui_t welcome_title)" --msgbox "$text" 18 76 || exit 1
}

ui_uplinks() {
    ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -Ev '^(lo|awg[0-9]+|wg[0-9]+|docker[0-9]*|veth.*|br-.*)$' || :
}

ui_password_screen() {
    local choice first second
    choice="$(ui_choice "$(ui_t i_password)" "$(ui_t pass_text)" "$([[ -n "$WIZ_PASSWORD" ]] && echo own || echo gen)" \
              gen "$(ui_t pass_gen)" own "$(ui_t pass_own)")" || return 0
    if [[ "$choice" == gen ]]; then WIZ_PASSWORD=''; return 0; fi
    while :; do
        first="$(ui_password "$(ui_t i_password)" "$(ui_t pass_input)")" || return 0
        if [[ ${#first} -lt 12 || ${#first} -gt 256 ]]; then ui_msg "$(ui_t error_title)" "$(ui_t pass_short)"; continue; fi
        second="$(ui_password "$(ui_t i_password)" "$(ui_t pass_repeat)")" || return 0
        if [[ "$first" != "$second" ]]; then ui_msg "$(ui_t error_title)" "$(ui_t pass_mismatch)"; continue; fi
        WIZ_PASSWORD="$first"; return 0
    done
}

ui_https_screen() {
    local choice value
    choice="$(ui_choice "$(ui_t i_https)" "$(ui_t https_text)" "$NGINX_MODE" \
              none "$(ui_t https_none)" self-signed "$(ui_t https_self)" existing "$(ui_t https_own)")" || return 0
    NGINX_MODE="$choice"
    [[ "$NGINX_MODE" == none ]] && return 0
    value="$(ui_input "$(ui_t i_https)" "$(ui_t https_host)" "${NGINX_HOST:-$ENDPOINT}")" && NGINX_HOST="$value"
    value="$(ui_input "$(ui_t i_https)" "$(ui_t https_port)" "$NGINX_HTTPS_PORT")" && NGINX_HTTPS_PORT="$value"
    if [[ "$NGINX_MODE" == existing ]]; then
        value="$(ui_input "$(ui_t i_https)" "$(ui_t https_cert)" "${NGINX_CERT:-/etc/letsencrypt/live/${NGINX_HOST}/fullchain.pem}")" && NGINX_CERT="$value"
        value="$(ui_input "$(ui_t i_https)" "$(ui_t https_key)" "${NGINX_KEY:-/etc/letsencrypt/live/${NGINX_HOST}/privkey.pem}")" && NGINX_KEY="$value"
    fi
}

# The settings menu. Returns once the administrator presses Install; exits on Cancel.
ui_configure() {
    local choice value items label
    while :; do
        case "$NGINX_MODE" in none) label="$(ui_t v_none)";; self-signed) label="$(ui_t https_self)";; *) label="$(ui_t https_own)";; esac
        items=(subnet "$(ui_t i_subnet): $SUBNET" port "$(ui_t i_port): $PORT" endpoint "$(ui_t i_endpoint): $ENDPOINT"
               dns "$(ui_t i_dns): $DNS" mode "$(ui_t i_mode): $([[ "$MODE" == full ]] && ui_t mode_full || ui_t mode_split)"
               uplink "$(ui_t i_uplink): $UPLINK" mtu "$(ui_t i_mtu): $MTU" panel "$(ui_t i_panel): $PANEL_PORT"
               client "$(ui_t i_client): ${FIRST_CLIENT:-$(ui_t v_none)}" https "$(ui_t i_https): $label"
               password "$(ui_t i_password): $([[ -n "$WIZ_PASSWORD" ]] && ui_t v_own || ui_t v_gen)")
        if [[ -n "$WIZ_FIREWALL" ]]; then
            # shellcheck disable=SC2059
            items+=(firewall "$(printf "$(ui_t i_firewall)" "$WIZ_FIREWALL"): $([[ "$AWG31_OPEN_FIREWALL" == no ]] && ui_t v_no || ui_t v_yes)")
        fi
        items+=(install "$(ui_t i_install)" cancel "$(ui_t i_cancel)")
        choice="$(wt --title "$(ui_t menu_title)" --default-item "${choice:-install}" --notags --menu "$(ui_t menu_text)" 24 78 15 "${items[@]}")" || choice=cancel
        case "$choice" in
            subnet)
                value="$(ui_choice "$(ui_t i_subnet)" "$(ui_t subnet_text)" default \
                         default "$(ui_t subnet_default)" random "$(ui_t subnet_random)" custom "$(ui_t subnet_custom)")" || continue
                case "$value" in
                    default) SUBNET='10.77.10.0/24' ;;
                    random) SUBNET="$(awg31_random_subnet)" ;;
                    custom) value="$(ui_input "$(ui_t i_subnet)" "$(ui_t subnet_input)" "$SUBNET")" && SUBNET="$value" ;;
                esac ;;
            port) value="$(ui_input "$(ui_t i_port)" "$(ui_t port_text)" "$PORT")" && PORT="$value" ;;
            endpoint) value="$(ui_input "$(ui_t i_endpoint)" "$(ui_t endpoint_text)" "$ENDPOINT")" && ENDPOINT="$value" ;;
            dns)
                value="$(ui_choice "$(ui_t i_dns)" "$(ui_t dns_text)" "$DNS" 1.1.1.1 'Cloudflare  1.1.1.1' 8.8.8.8 'Google  8.8.8.8' \
                         9.9.9.9 'Quad9  9.9.9.9' 94.140.14.14 'AdGuard  94.140.14.14' custom "$(ui_t dns_custom)")" || continue
                if [[ "$value" == custom ]]; then value="$(ui_input "$(ui_t i_dns)" "$(ui_t dns_input)" "$DNS")" || continue; fi
                DNS="$value" ;;
            mode) value="$(ui_choice "$(ui_t i_mode)" "$(ui_t mode_text)" "$MODE" full "$(ui_t mode_full)" split "$(ui_t mode_split)")" && MODE="$value" ;;
            uplink)
                local links=() name
                while read -r name; do [[ -n "$name" ]] && links+=("$name" "$name"); done < <(ui_uplinks)
                if [[ ${#links[@]} -gt 0 ]]; then
                    value="$(ui_choice "$(ui_t i_uplink)" "$(ui_t uplink_text)" "$UPLINK" "${links[@]}")" && UPLINK="$value"
                else
                    value="$(ui_input "$(ui_t i_uplink)" "$(ui_t uplink_text)" "$UPLINK")" && UPLINK="$value"
                fi ;;
            mtu) value="$(ui_input "$(ui_t i_mtu)" "$(ui_t mtu_text)" "$MTU")" && MTU="$value" ;;
            panel) value="$(ui_input "$(ui_t i_panel)" "$(ui_t panel_text)" "$PANEL_PORT")" && PANEL_PORT="$value" ;;
            client) value="$(ui_input "$(ui_t i_client)" "$(ui_t client_text)" "$FIRST_CLIENT")" && FIRST_CLIENT="$value" ;;
            https) ui_https_screen ;;
            password) ui_password_screen ;;
            firewall)
                # shellcheck disable=SC2059
                if ui_yesno "$WIZ_FIREWALL" "$(printf "$(ui_t fw_text)" "$WIZ_FIREWALL")"; then AWG31_OPEN_FIREWALL=yes; else AWG31_OPEN_FIREWALL=no; fi ;;
            install)
                local problem
                if problem="$(wizard_check 2>&1)"; then return 0; fi
                ui_msg "$(ui_t error_title)" "$(printf '%s\n' "$problem" | grep -Ev '^Параметры проверены|installation failed at line' | tail -n 3)" ;;
            cancel|'')
                if ui_yesno "$(ui_t i_cancel)" "$(ui_t cancel_text)"; then echo 'Установка отменена'; exit 1; fi ;;
        esac
    done
}

# ---------------------------------------------------------------- progress
ui_progress_start() {
    install -d -m 700 "$(dirname "$WIZ_LOG")"
    : >"$WIZ_LOG"; chmod 600 "$WIZ_LOG"
    WIZ_GAUGE_FIFO="$(mktemp -u /tmp/awg31-gauge.XXXXXX)"
    mkfifo -m 600 "$WIZ_GAUGE_FIFO"
    # The bar reads its updates from the FIFO and draws on the terminal we started on.
    local title
    # shellcheck disable=SC2059
    printf -v title "$(ui_t gauge_title)" "$WIZ_LOG"
    whiptail --backtitle "$(ui_t backtitle)" --title "$title" --gauge "$(ui_t s_deps)" 8 76 0 \
        <"$WIZ_GAUGE_FIFO" >"$WIZ_TTY" 2>&1 &
    WIZ_GAUGE_PID=$!
    exec 7>"$WIZ_GAUGE_FIFO"
    exec 5>&1 6>&2
    exec >>"$WIZ_LOG" 2>&1
}

# ui_progress PERCENT KEY: move the bar (the log gets the step too).
ui_progress() {
    local text; text="$(ui_t "s_$2")"
    echo "=== $text ==="
    if [[ -n "$WIZ_GAUGE_PID" ]]; then
        # shellcheck disable=SC2059
        printf 'XXX\n%s\n%s\nXXX\n' "$1" "$text" >&7 2>/dev/null || :
    fi
}

ui_progress_stop() {
    [[ -n "$WIZ_GAUGE_PID" ]] || return 0
    exec 7>&- 2>/dev/null || :
    wait "$WIZ_GAUGE_PID" 2>/dev/null || :
    WIZ_GAUGE_PID=''
    rm -f -- "$WIZ_GAUGE_FIFO"
    exec 1>&5 2>&6
    clear 2>/dev/null || :
}

ui_failed() {
    ui_progress_stop
    # shellcheck disable=SC2059
    printf "\n$(ui_t failed)\n" "$WIZ_LOG" >&2
    tail -n 25 "$WIZ_LOG" >&2 || :
}
