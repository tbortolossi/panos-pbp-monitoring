#!/usr/bin/env bash
# Produce one support archive for a deployment, including what the collector
# cannot see from inside its container: the state of the three services, the
# ports actually published on this host, the output of the Syslog gateway, the
# image in use, and the Docker and host versions.
#
# Run it from the directory holding compose.yaml, on the Docker host:
#
#   ./pbp-support.sh                       # complete archive
#   ./pbp-support.sh --anonymize           # addresses, serials and names tokenized
#   ./pbp-support.sh --output /tmp/x.zip   # choose where to write it
#
# With --anonymize the token mapping is written beside the archive, as
# <archive>.mapping.csv. Keep that file: it is the one thing that must never be
# sent. Nothing here contacts a firewall, and nothing here changes the stack.
set -euo pipefail

anonymize=""
output=""
while [ $# -gt 0 ]; do
    case "$1" in
        --anonymize) anonymize="--anonymize" ;;
        --output) shift; output="${1:-}" ;;
        --output=*) output="${1#--output=}" ;;
        -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [ -z "$output" ]; then
    output="pbp-support-${anonymize:+anonymized-}${stamp}.zip"
fi
mapping="${output%.zip}.mapping.csv"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is not installed or not on PATH" >&2
    exit 1
fi
compose() { docker compose "$@"; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
evidence="$work/host"
mkdir -p "$evidence"

# Every command below is read-only. A command that fails still leaves a file,
# so the maintainer sees that it was attempted and why it produced nothing.
gather() {
    local name="$1"; shift
    { "$@" ; } >"$evidence/$name" 2>&1 || echo "[exit status $? for: $*]" >>"$evidence/$name"
}

gather host.txt sh -c 'date -u; echo; uname -a; echo; cat /etc/os-release 2>/dev/null; echo; uptime 2>/dev/null; echo; df -h 2>/dev/null'
gather docker-version.txt sh -c 'docker version; echo; docker compose version; echo; docker info --format "{{.ServerVersion}} {{.OSType}}/{{.Architecture}} storage={{.Driver}} cgroup={{.CgroupDriver}}" 2>/dev/null'
gather compose-ps.txt compose ps -a
gather compose-ps.json compose ps -a --format json
gather compose-config.yaml compose config
gather compose-images.txt compose images
gather images.txt sh -c 'for image in $(docker compose images --quiet 2>/dev/null | sort -u); do docker image inspect --format "{{.Id}} created={{.Created}} digests={{.RepoDigests}} labels={{json .Config.Labels}}" "$image"; done'
gather containers.json sh -c 'ids=$(docker compose ps -aq); [ -n "$ids" ] && docker inspect --format "{{json .}}" $ids | sed -E "s/\"(Env|Args|Cmd)\":\[[^]]*\]/\"\1\":\"[omitted]\"/g"'
gather ports.txt sh -c 'docker compose ps --format "table {{.Service}}\t{{.Status}}\t{{.Ports}}"; echo; (ss -lunp 2>/dev/null || netstat -lunp 2>/dev/null) | grep -E ":(514|1514|5514)\b" || echo "no listener found on 514/1514/5514 with ss or netstat"'
gather syslog-gateway.log compose logs --no-color --timestamps --tail 500 syslog-gateway
gather collector-stdout.log compose logs --no-color --timestamps --tail 300 collector
gather webui-stdout.log compose logs --no-color --timestamps --tail 300 webui

# The collector builds the bundle around the host evidence, so one archive
# leaves the site. If the collector is not running — the very case a crash at
# startup produces — a one-off container is started on the same volumes. If
# even the image is absent, the host layer alone is sent as a tar archive.
tar -C "$evidence" -cf "$work/host.tar" .

run_bundle() {
    local mode="$1"
    case "$mode" in
        exec) compose exec -T collector pbp-support $anonymize --host-evidence - ${anonymize:+--mapping /tmp/pbp-support-mapping.csv} ;;
        run) compose run --rm --no-deps -T collector pbp-support $anonymize --host-evidence - ${anonymize:+--mapping /tmp/pbp-support-mapping.csv} ;;
    esac
}

fetch_mapping() {
    [ -n "$anonymize" ] || return 0
    case "$1" in
        exec) compose exec -T collector sh -c 'cat /tmp/pbp-support-mapping.csv && rm -f /tmp/pbp-support-mapping.csv' >"$mapping" ;;
        run) return 0 ;;
    esac
}

if run_bundle exec <"$work/host.tar" >"$work/bundle.zip" 2>"$work/exec.err"; then
    mv "$work/bundle.zip" "$output"
    fetch_mapping exec || true
elif run_bundle run <"$work/host.tar" >"$work/bundle.zip" 2>"$work/run.err"; then
    mv "$work/bundle.zip" "$output"
    echo "note: the collector was not running; the bundle came from a one-off container on the same volumes" >&2
elif tar -C "$work" -czf "${output%.zip}-host-only.tar.gz" host; then
    output="${output%.zip}-host-only.tar.gz"
    echo "note: the collector image is unavailable; only the host layer could be gathered" >&2
    cat "$work/exec.err" "$work/run.err" >&2 2>/dev/null || true
fi

if [ -n "$anonymize" ] && [ ! -s "$mapping" ]; then
    # The one-off container has no reachable /tmp afterwards: produce the
    # mapping in a second one-off run. The salt is persistent, so it is the same.
    compose run --rm --no-deps -T collector pbp-support --anonymize --output /dev/null --mapping /dev/stdout 2>/dev/null >"$mapping" || rm -f "$mapping"
fi

echo "Support archive: $output"
if [ -n "$anonymize" ]; then
    if [ -s "$mapping" ]; then
        chmod 600 "$mapping" 2>/dev/null || true
        echo "Token mapping:   $mapping   (keep it, never send it)"
    else
        echo "Token mapping could not be produced; use 'Download token mapping' on the admin page" >&2
    fi
fi
