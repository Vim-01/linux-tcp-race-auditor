// Package tui implements the bubbletea terminal UI. i18n.go holds
// the bilingual (RU/EN) string tables.
package tui

type L10n struct {
	lang string
	m    map[string]string
}

func NewL10n(lang string) *L10n {
	ru := map[string]string{
		"title":               "CVE-2026-98432 — UAF IPv4/TCP (учебный эксплоит)",
		"subtitle":            "гонка SYN/ретрансмиссия: ireq_opt освобождается под rcu_read_lock",
		"page_target":         "ЦЕЛЬ",
		"page_payload":        "ПАГЛОД И ТАЙМИНГИ",
		"page_fire":           "АТАКА",
		"page_result":         "ИТОГИ",
		"target_ip":           "IP цели",
		"target_port":         "Порт цели",
		"kernel_ver":          "Версия ядра (справочно)",
		"mode":                "Режим",
		"mode_hammer":         "hammer — базовый триггер (SYN -> Δt -> ретранс)",
		"mode_spray":          "spray — агрессивный churn kmalloc-96",
		"mode_mptcp":          "mptcp — на MPTCP-листенер (эксперимент)",
		"mode_handshake":      "handshake — полный handshake + RST, 2 pinned CPU (fire #2; params в TOML [handshake])",
		"opt_preset":          "IP-опции (пресет)",
		"opt_custom":          "IP-опции (hex, для custom)",
		"ttl":                 "TTL",
		"window":              "TCP Window",
		"tcpipt":              "TCP-опции MSS/SACK/WS",
		"src_ip":              "Source IP (bind, пусто = авто по маршруту)",
		"delta":               "Δt SYN->ретранс (мкс)",
		"flows":               "Параллельные потоки",
		"gap":                 "Пауза потока (мс)",
		"duration":            "Длительность (сек)",
		"on":                  "вкл",
		"off":                 "выкл",
		"nav":                 "TAB/←→ стр. | ↑↓ поле | ENTER далее | L язык | Q выход",
		"fire_hint":           "SPACE старт/стоп | R результат | L язык | Q выход",
		"status_idle":         "ОЖИДАНИЕ",
		"status_firing":       "ВЕДЁТ ОБСТРЕЛ",
		"status_done":         "ОСТАНОВЛЕНО",
		"stat_elapsed":        "Время",
		"stat_syn":            "SYN отправлено",
		"stat_rtx":            "Ретрансмиссий",
		"stat_pps":            "Пакетов/сек",
		"stat_synack":         "SYN-ACK получено",
		"stat_rst":            "RST получено",
		"stat_err":            "Ошибок отправки",
		"silent":              "ТИШИНА: ответ нет > 2с",
		"events":              "События",
		"err_need_root":       "Нужен CAP_NET_RAW: запусти с sudo или setcap cap_net_raw+ep",
		"err_validation":      "Ошибка валидации",
		"result_title":        "ИТОГИ ПРОГОНА",
		"result_note":         "Hit UAF извне не виден. Проверь на цели: dmesg | grep -i kasan / crash log. Тишина цели после обстрела - вероятный признак срабатывания.",
		"result_advice":       "Митигация до патча: nft drop ip protocol tcp ip hdrlength > 5",
		"quit_confirm":        "Выйти? (Y/n)",
		"dry_run":             "DRY RUN: пакеты не отправлялись",
		"lang":                "Язык",
		"footer":              "УЧЕБНАЯ ПРОГРАММА - тестируй только СВОЮ инфраструктуру. MIT. Подробности: README/DISCLAIMER.",
		"preset_hint":         "nop|ts|rr|ssrr|custom (hex)",
		"started":             "запуск",
		"stopped":             "остановка",
		"engine_start_failed": "Не удалось запустить движок",
	}
	en := map[string]string{
		"title":               "CVE-2026-98432 - IPv4/TCP UAF (educational exploit)",
		"subtitle":            "SYN/retransmit race: ireq_opt freed under rcu_read_lock only",
		"page_target":         "TARGET",
		"page_payload":        "PAYLOAD & TIMING",
		"page_fire":           "ATTACK",
		"page_result":         "RESULTS",
		"target_ip":           "Target IP",
		"target_port":         "Target port",
		"kernel_ver":          "Kernel version (info)",
		"mode":                "Mode",
		"mode_hammer":         "hammer - basic trigger (SYN -> dt -> retrans)",
		"mode_spray":          "spray - aggressive kmalloc-96 churn",
		"mode_mptcp":          "mptcp - at an MPTCP listener (experimental)",
		"mode_handshake":      "handshake - full handshake + RST, 2 pinned CPUs (fire #2; params in TOML [handshake])",
		"opt_preset":          "IP options (preset)",
		"opt_custom":          "IP options (hex, for custom)",
		"ttl":                 "TTL",
		"window":              "TCP Window",
		"tcpipt":              "TCP opts MSS/SACK/WS",
		"src_ip":              "Source IP (bind, empty = auto egress)",
		"delta":               "dt SYN->retrans (us)",
		"flows":               "Parallel flows",
		"gap":                 "Flow gap (ms)",
		"duration":            "Duration (sec)",
		"on":                  "on",
		"off":                 "off",
		"nav":                 "TAB/<> page | UP/DOWN field | ENTER next | L lang | Q quit",
		"fire_hint":           "SPACE start/stop | R results | L lang | Q quit",
		"status_idle":         "IDLE",
		"status_firing":       "FIRING",
		"status_done":         "STOPPED",
		"stat_elapsed":        "Elapsed",
		"stat_syn":            "SYN sent",
		"stat_rtx":            "Retransmits",
		"stat_pps":            "Packets/sec",
		"stat_synack":         "SYN-ACK received",
		"stat_rst":            "RST received",
		"stat_err":            "Send errors",
		"silent":              "SILENCE: no reply > 2s",
		"events":              "Events",
		"err_need_root":       "CAP_NET_RAW required: run with sudo or setcap cap_net_raw+ep",
		"err_validation":      "Validation error",
		"result_title":        "RUN SUMMARY",
		"result_note":         "A UAF hit is not directly visible from the attacker side. On the target check: dmesg | grep -i kasan / crash log. Target silence after the run is a likely indicator.",
		"result_advice":       "Mitigation before patch: nft drop ip protocol tcp ip hdrlength > 5",
		"quit_confirm":        "Quit? (Y/n)",
		"dry_run":             "DRY RUN: no packets were sent",
		"lang":                "Language",
		"footer":              "EDUCATIONAL TOOL - test ONLY your own infrastructure. MIT. See README/DISCLAIMER.",
		"preset_hint":         "nop|ts|rr|ssrr|custom (hex)",
		"started":             "start",
		"stopped":             "stop",
		"engine_start_failed": "Engine start failed",
	}
	m := ru
	if lang == "en" {
		m = en
	}
	return &L10n{lang: lang, m: m}
}

func (l *L10n) T(key string) string {
	if v, ok := l.m[key]; ok {
		return v
	}
	return key
}

func (l *L10n) Lang() string { return l.lang }

func (l *L10n) Toggle() *L10n {
	if l.lang == "ru" {
		return NewL10n("en")
	}
	return NewL10n("ru")
}
