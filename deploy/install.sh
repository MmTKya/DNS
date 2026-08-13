#!/usr/bin/env bash
#
# SedDNS installer.
#
#   curl -sSL https://raw.githubusercontent.com/MmTKya/DNS/main/deploy/install.sh | bash
#
# The whole script is one function that is only called on the very last line.
# That is deliberate: if the download is truncated part-way, bash reaches the
# end of the partial file without ever invoking anything, so a half-downloaded
# installer does half of nothing instead of half of the install.
#
# Options:
#   --unattended, -y   do not prompt; accept the printed plan
#   --version X.Y.Z    install a specific release instead of the latest
#   --from-file PATH   install a local archive or binary instead of downloading
#   --free-port-53     disable a conflicting DNS stub listener without asking
#   --uninstall        remove the service, binary and unit (keeps data/config)
#   --dry-run          print the plan and exit without changing anything

aegisdns_install() {
	set -euo pipefail

	readonly REPO="MmTKya/DNS"
	readonly BIN_DIR="/usr/local/bin"
	readonly BIN_PATH="${BIN_DIR}/aegisdns"
	readonly CONFIG_DIR="/etc/aegisdns"
	readonly CONFIG_PATH="${CONFIG_DIR}/aegisdns.yaml"
	readonly DATA_DIR="/var/lib/aegisdns"
	readonly UNIT_PATH="/etc/systemd/system/aegisdns.service"
	readonly UPDATE_UNIT_PATH="/etc/systemd/system/aegisdns-update.service"
	readonly UPDATE_PATH_UNIT="/etc/systemd/system/aegisdns-update.path"
	readonly SERVICE_USER="aegisdns"

	local unattended=0 dry_run=0 do_uninstall=0 free_port=0
	local requested_version="" local_file=""

	# Deliberately not local: the EXIT trap below fires after this function has
	# returned, when its locals no longer exist.
	tmp_dir=""

	# ---------------------------------------------------------------- output

	local bold red green yellow dim reset
	if [ -t 1 ]; then
		bold=$'\033[1m' red=$'\033[31m' green=$'\033[32m'
		yellow=$'\033[33m' dim=$'\033[2m' reset=$'\033[0m'
	else
		bold="" red="" green="" yellow="" dim="" reset=""
	fi

	say() { printf '%s\n' "$*"; }
	step() { printf '%s==>%s %s\n' "${bold}" "${reset}" "$*"; }
	warn() { printf '%s warn:%s %s\n' "${yellow}" "${reset}" "$*" >&2; }
	die() {
		printf '%serror:%s %s\n' "${red}" "${reset}" "$*" >&2
		exit 1
	}

	cleanup() {
		[ -n "${tmp_dir:-}" ] && [ -d "${tmp_dir}" ] && rm -rf "${tmp_dir}"

		return 0
	}
	trap cleanup EXIT

	# ------------------------------------------------------------- arguments

	while [ $# -gt 0 ]; do
		case "$1" in
		--unattended | -y) unattended=1 ;;
		--dry-run) dry_run=1 ;;
		--uninstall) do_uninstall=1 ;;
		--free-port-53) free_port=1 ;;
		--version)
			[ $# -ge 2 ] || die "--version needs a value"
			requested_version="$2"
			shift
			;;
		--version=*) requested_version="${1#*=}" ;;
		--from-file)
			[ $# -ge 2 ] || die "--from-file needs a path"
			local_file="$2"
			shift
			;;
		--from-file=*) local_file="${1#*=}" ;;
		-h | --help)
			say "SedDNS installer"
			say ""
			say "  --unattended, -y   do not prompt; accept the printed plan"
			say "  --version X.Y.Z    install a specific release instead of the latest"
			say "  --from-file PATH   install a local archive or binary you built yourself"
			say "  --free-port-53     disable a conflicting DNS stub listener without asking"
			say "  --uninstall        remove the service, binary and unit (keeps data/config)"
			say "  --dry-run          print the plan and exit without changing anything"

			return 0
			;;
		*) die "unknown option: $1" ;;
		esac
		shift
	done

	# ------------------------------------------------------------ privileges
	#
	# Only the modes that actually change the system need root.  --dry-run and
	# --help stay usable as an ordinary user, which is the whole point of
	# offering them to someone who has just been told to pipe a script into
	# their shell.

	if [ "${dry_run}" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
		# Piped through `curl | bash`, $0 is the shell itself and there is no
		# file to hand to sudo, so say what to type instead of failing on an
		# exec that cannot work.
		if [ -r "$0" ] && [ -f "$0" ]; then
			step "Re-running with sudo"
			exec sudo bash "$0" "$@"
		fi

		die "this installer needs root. Re-run it as:
    curl -sSL https://raw.githubusercontent.com/${REPO}/main/deploy/install.sh | sudo bash"
	fi

	# ------------------------------------------------------ platform support

	require_cmd() {
		command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"
	}
	[ -n "${local_file}" ] || require_cmd curl
	require_cmd tar
	require_cmd sha256sum
	require_cmd systemctl

	local arch
	case "$(uname -m)" in
	x86_64 | amd64) arch="amd64" ;;
	aarch64 | arm64) arch="arm64" ;;
	armv7l | armv6l | armhf) arch="armv7" ;;
	*) die "unsupported architecture: $(uname -m). SedDNS ships amd64, arm64 and armv7." ;;
	esac

	[ "$(uname -s)" = "Linux" ] || die "SedDNS runs on Linux only"

	local os_name="unknown"
	if [ -r /etc/os-release ]; then
		# shellcheck disable=SC1091
		os_name="$(. /etc/os-release && printf '%s %s' "${NAME}" "${VERSION_ID:-}")"
	fi

	# --------------------------------------------------------------- uninstall

	if [ "${do_uninstall}" -eq 1 ]; then
		step "Removing SedDNS"
		systemctl stop aegisdns 2>/dev/null || true
		systemctl disable aegisdns 2>/dev/null || true
		systemctl stop aegisdns-update.path 2>/dev/null || true
		systemctl disable aegisdns-update.path 2>/dev/null || true
		rm -f "${UNIT_PATH}" "${UPDATE_UNIT_PATH}" "${UPDATE_PATH_UNIT}" "${BIN_PATH}"
		systemctl daemon-reload
		say "Removed the service and binary."
		say "Left in place: ${CONFIG_DIR} and ${DATA_DIR} (delete them by hand if you are done)."

		return 0
	fi

	# ---------------------------------------------------------------- version

	local version="${requested_version}"
	if [ -n "${local_file}" ]; then
		[ -r "${local_file}" ] || die "cannot read ${local_file}"
		local_file="$(cd "$(dirname "${local_file}")" && pwd)/$(basename "${local_file}")"
		[ -n "${version}" ] || version="local"
	elif [ -z "${version}" ]; then
		step "Looking up the latest release"
		version="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
			sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
		[ -n "${version}" ] || die "could not determine the latest release; pass --version X.Y.Z"
	fi
	version="${version#v}"

	local archive="aegisdns_${version}_linux_${arch}.tar.gz"
	local base_url="https://github.com/${REPO}/releases/download/v${version}"

	# ------------------------------------------------------- conflict checks

	# Port 53 is almost always already taken on a modern desktop distro, and
	# this is the single most common reason a first install fails.
	local port_holder=""
	if command -v ss >/dev/null 2>&1; then
		port_holder="$(ss -lunp 2>/dev/null | awk '$5 ~ /:53$/ {print $NF}' | head -1)"
	fi

	local resolved_stub=0 dnsmasq_running=0
	if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
		# The stub listener, not the service itself, is what holds 127.0.0.53:53.
		if [ -z "$(grep -rhs '^ *DNSStubListener *= *no' /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/ 2>/dev/null)" ]; then
			resolved_stub=1
		fi
	fi
	if systemctl is-active --quiet dnsmasq 2>/dev/null; then
		dnsmasq_running=1
	fi

	local upgrade=0
	[ -x "${BIN_PATH}" ] && upgrade=1

	# ------------------------------------------------------------- the plan

	say ""
	say "${bold}SedDNS ${version}${reset}  ${dim}(${arch}, ${os_name})${reset}"
	say ""
	say "This will:"
	if [ "${upgrade}" -eq 1 ]; then
		say "  • replace the binary at ${BIN_PATH} ($("${BIN_PATH}" --version 2>/dev/null | head -1 || echo 'unknown version'))"
	else
		say "  • install ${BIN_PATH}"
		say "  • create the system user '${SERVICE_USER}' (no login shell)"
	fi
	if [ -n "${local_file}" ]; then
		say "  • install from ${local_file} ${yellow}(no checksum or signature check)${reset}"
	else
		say "  • download ${archive} and verify it against the release checksums"
	fi
	[ -f "${CONFIG_PATH}" ] &&
		say "  • keep your existing config at ${CONFIG_PATH}" ||
		say "  • write a default config to ${CONFIG_PATH}"
	say "  • create ${DATA_DIR} for the database"
	say "  • install and enable the systemd unit ${UNIT_PATH}"
	say "  • install the update watcher, so the panel can apply updates without"
	say "    the resolver itself being able to rewrite its own binary"

	if [ "${resolved_stub}" -eq 1 ]; then
		say ""
		say "  ${yellow}Port 53 conflict:${reset} systemd-resolved's stub listener is running."
		if [ "${free_port}" -eq 1 ]; then
			say "  • disable DNSStubListener and restart systemd-resolved"
			say "  • repoint /etc/resolv.conf at resolved's real upstreams, so this"
			say "    machine keeps resolving once the stub is gone"
		else
			say "  ${dim}SedDNS cannot bind port 53 until it is disabled. Re-run with"
			say "  --free-port-53 to have this installer do it, or do it yourself:"
			say "    printf '[Resolve]\\nDNSStubListener=no\\n' > /etc/systemd/resolved.conf.d/aegisdns.conf"
			say "    systemctl restart systemd-resolved${reset}"
		fi
	fi
	if [ "${dnsmasq_running}" -eq 1 ]; then
		say ""
		say "  ${yellow}Port 53 conflict:${reset} dnsmasq is running and will keep the port."
		say "  ${dim}Stop it, or point SedDNS at another port in ${CONFIG_PATH}.${reset}"
	fi
	if [ -n "${port_holder}" ] && [ "${resolved_stub}" -eq 0 ] && [ "${dnsmasq_running}" -eq 0 ]; then
		say ""
		say "  ${yellow}Port 53 is already in use${reset} by: ${port_holder}"
	fi
	say ""

	if [ "${dry_run}" -eq 1 ]; then
		say "${dim}--dry-run: nothing was changed.${reset}"

		return 0
	fi

	if [ "${unattended}" -eq 0 ]; then
		# Under `curl … | sudo bash` stdin is the script itself, so reading the
		# answer from it would consume the rest of the installer. The terminal
		# is still there — it is just not on stdin — so ask it directly.
		# Without this the documented one-line install can never prompt, which
		# would leave --unattended as the only way to run it: exactly the
		# habit an installer should not be teaching.
		local prompt_from=""
		if [ -t 0 ]; then
			prompt_from="/dev/stdin"
		elif (exec 3</dev/tty) 2>/dev/null; then
			# Opened, not just stat'd: with no controlling terminal /dev/tty
			# still passes -r and -c but fails to open, which would surface as
			# a raw "No such device or address" instead of the message below.
			prompt_from="/dev/tty"
		else
			die "no terminal to confirm on. Re-run with --unattended, or download the script and run it directly."
		fi

		printf 'Continue? [y/N] '
		local answer=""
		read -r answer <"${prompt_from}" || answer=""
		case "${answer}" in
		[yY] | [yY][eE][sS]) ;;
		*) die "aborted" ;;
		esac
	fi

	# -------------------------------------------------------------- download

	tmp_dir="$(mktemp -d)"

	if [ -n "${local_file}" ]; then
		# A binary you compiled and copied here yourself. There is nothing to
		# verify it against, and pretending otherwise would be theatre — so the
		# plan above says plainly that this path is unverified.
		step "Installing from ${local_file}"
		case "${local_file}" in
		*.tar.gz | *.tgz) tar -xzf "${local_file}" -C "${tmp_dir}" ;;
		*) install -m 0755 "${local_file}" "${tmp_dir}/aegisdns" ;;
		esac
	else
		step "Downloading ${archive}"
		curl -fsSL --retry 3 --retry-delay 2 -o "${tmp_dir}/${archive}" "${base_url}/${archive}" ||
			die "download failed: ${base_url}/${archive}"

		step "Verifying checksum"
		curl -fsSL --retry 3 --retry-delay 2 -o "${tmp_dir}/checksums.txt" "${base_url}/checksums.txt" ||
			die "could not download checksums.txt; refusing to install an unverified binary"

		(
			cd "${tmp_dir}"
			# TLS alone is not enough: a compromised mirror or CDN would otherwise
			# own every install. Only the line for our archive is checked, because
			# the file lists every architecture.
			grep " ${archive}\$" checksums.txt >expected.txt || die "no checksum published for ${archive}"
			sha256sum -c expected.txt >/dev/null 2>&1 || die "checksum mismatch for ${archive}; not installing"
		)
		say "  ${green}ok${reset} — archive matches the published checksum"

		if command -v cosign >/dev/null 2>&1; then
			step "Verifying signature"
			if curl -fsSL -o "${tmp_dir}/checksums.txt.sig" "${base_url}/checksums.txt.sig" 2>/dev/null &&
				curl -fsSL -o "${tmp_dir}/checksums.txt.pem" "${base_url}/checksums.txt.pem" 2>/dev/null; then
				if cosign verify-blob \
					--certificate "${tmp_dir}/checksums.txt.pem" \
					--signature "${tmp_dir}/checksums.txt.sig" \
					--certificate-identity-regexp "https://github.com/${REPO}" \
					--certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
					"${tmp_dir}/checksums.txt" >/dev/null 2>&1; then
					say "  ${green}ok${reset} — checksums signed by the release pipeline"
				else
					die "signature verification failed; not installing"
				fi
			else
				warn "no signature published for this release; continuing on checksum alone"
			fi
		fi

		tar -xzf "${tmp_dir}/${archive}" -C "${tmp_dir}"
	fi

	[ -f "${tmp_dir}/aegisdns" ] || die "no aegisdns binary found in ${local_file:-${archive}}"
	chmod 0755 "${tmp_dir}/aegisdns"

	# Catches the classic mistake of copying an amd64 build onto a Pi: the
	# install would succeed and only systemd would report the failure.
	"${tmp_dir}/aegisdns" --version >/dev/null 2>&1 ||
		die "that binary does not run on this machine (wrong architecture? expected ${arch})"

	# ------------------------------------------------------------- install

	if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
		step "Creating the ${SERVICE_USER} system user"
		useradd --system --no-create-home --home-dir "${DATA_DIR}" \
			--shell /usr/sbin/nologin "${SERVICE_USER}"
	fi

	step "Installing ${BIN_PATH}"
	install -o root -g root -m 0755 "${tmp_dir}/aegisdns" "${BIN_PATH}.new"
	# Rename is atomic, so a running node is never left with a partial binary.
	mv -f "${BIN_PATH}.new" "${BIN_PATH}"

	install -d -o root -g "${SERVICE_USER}" -m 0750 "${CONFIG_DIR}"
	install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0750 "${DATA_DIR}"

	if [ -f "${CONFIG_PATH}" ]; then
		say "  keeping the existing config at ${CONFIG_PATH}"
	else
		step "Writing ${CONFIG_PATH}"
		if [ -f "${tmp_dir}/deploy/aegisdns.example.yaml" ]; then
			install -o root -g "${SERVICE_USER}" -m 0640 \
				"${tmp_dir}/deploy/aegisdns.example.yaml" "${CONFIG_PATH}"
		else
			cat >"${CONFIG_PATH}" <<-'YAML'
				mode: dns-only
				log:
				  level: info
				  format: text
				dns:
				  listen:
				    - "0.0.0.0:53"
				  upstreams:
				    - "9.9.9.9"
				    - "149.112.112.112"
				  bootstrap:
				    - "9.9.9.9"
				    - "149.112.112.112"
				  upstream_mode: load_balance
				  upstream_timeout: 10s
				  cache_enabled: true
				  cache_size_bytes: 4194304
				  refuse_any: true
				http:
				  listen: "0.0.0.0:8080"
				store:
				  path: "/var/lib/aegisdns/aegisdns.db"
			YAML
			chown root:"${SERVICE_USER}" "${CONFIG_PATH}"
			chmod 0640 "${CONFIG_PATH}"
		fi
	fi

	"${BIN_PATH}" --config "${CONFIG_PATH}" --check-config >/dev/null ||
		die "the installed configuration is not valid; the service was not started"

	step "Installing the systemd unit"
	if [ -f "${tmp_dir}/deploy/aegisdns.service" ]; then
		install -o root -g root -m 0644 "${tmp_dir}/deploy/aegisdns.service" "${UNIT_PATH}"
	else
		die "the archive did not contain deploy/aegisdns.service"
	fi

	# The privileged half of a self-update. The node runs unprivileged and
	# cannot write /usr/local/bin; it stages a verified release and this pair
	# performs the swap, verifying it again first. Optional on purpose: without
	# them the panel reports updates and declines to apply them, which is a
	# better failure than a resolver that can rewrite its own binary.
	if [ -f "${tmp_dir}/deploy/aegisdns-update.service" ] && [ -f "${tmp_dir}/deploy/aegisdns-update.path" ]; then
		step "Installing the update watcher"
		install -o root -g root -m 0644 "${tmp_dir}/deploy/aegisdns-update.service" "${UPDATE_UNIT_PATH}"
		install -o root -g root -m 0644 "${tmp_dir}/deploy/aegisdns-update.path" "${UPDATE_PATH_UNIT}"
	fi

	# --------------------------------------------------------- port 53 fix

	if [ "${resolved_stub}" -eq 1 ] && [ "${free_port}" -eq 1 ]; then
		step "Disabling the systemd-resolved stub listener"
		mkdir -p /etc/systemd/resolved.conf.d
		printf '[Resolve]\nDNSStubListener=no\n' >/etc/systemd/resolved.conf.d/aegisdns.conf

		# On Ubuntu and friends /etc/resolv.conf is a symlink to the stub file,
		# which points at 127.0.0.53 — the listener we just switched off. Left
		# alone, the machine loses name resolution the moment resolved
		# restarts: apt stops working and SedDNS cannot download a single
		# feed, because Go's resolver reads this same file.
		#
		# resolved still writes the real upstream servers to resolv.conf in the
		# same directory, so pointing at that keeps the host resolving without
		# making it depend on SedDNS being up.
		if [ -L /etc/resolv.conf ]; then
			case "$(readlink /etc/resolv.conf)" in
			*stub-resolv.conf)
				step "Repointing /etc/resolv.conf away from the disabled stub"
				ln -sf ../run/systemd/resolve/resolv.conf /etc/resolv.conf
				;;
			esac
		fi

		systemctl restart systemd-resolved || warn "could not restart systemd-resolved"

		# Prove it rather than assume it: a host that cannot resolve is the
		# difference between a working install and empty blocklists.
		if command -v getent >/dev/null 2>&1 &&
			! getent hosts deb.debian.org >/dev/null 2>&1 &&
			! getent hosts github.com >/dev/null 2>&1; then
			warn "this machine can no longer resolve names. Feeds will not download."
			warn "Check /etc/resolv.conf — it should list a reachable nameserver."
		fi
	fi

	# ------------------------------------------------------------- start up

	systemctl daemon-reload
	systemctl enable aegisdns >/dev/null 2>&1
	if [ -f "${UPDATE_PATH_UNIT}" ]; then
		systemctl enable --now aegisdns-update.path >/dev/null 2>&1 ||
			warn "the update watcher did not start; updates will report but not apply"
	fi

	step "Starting aegisdns"
	if systemctl restart aegisdns; then
		sleep 1
		if systemctl is-active --quiet aegisdns; then
			local host_ip
			host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
			[ -n "${host_ip}" ] || host_ip="<this-host>"

			say ""
			say "${green}SedDNS ${version} is running.${reset}"
			say ""
			say "  Panel:  http://${host_ip}:8080"
			say "  DNS:    ${host_ip}:53"
			say ""
			say "  ${dim}Point your router's DHCP DNS server at ${host_ip}, or set it on a"
			say "  single device first to try it out."
			say ""
			say "  Logs:    journalctl -u aegisdns -f"
			say "  Config:  ${CONFIG_PATH}  (systemctl reload aegisdns after editing)${reset}"
			say ""

			return 0
		fi
	fi

	say ""
	warn "the service did not come up. The last log lines were:"
	journalctl -u aegisdns -n 20 --no-pager 2>/dev/null || true

	return 1
}

aegisdns_install "$@"
