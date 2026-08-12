#!/usr/bin/env bash
#
# Extracts one version's section from CHANGELOG.md.
#
# The panel shows whatever the release carries, so this is what someone reads
# before replacing the resolver their household depends on. A missing section
# is a failure rather than an empty release: shipping "## Changelog" followed
# by a commit hash is how the notes stopped being useful in the first place.

set -euo pipefail

version="${1#v}"
changelog="${2:-CHANGELOG.md}"

if [ -z "${version}" ]; then
	echo "usage: release-notes.sh <version> [changelog]" >&2
	exit 2
fi

# Blank lines are buffered rather than printed, so the ones inside the section
# survive and the ones padding either end do not. Trimming afterwards with tac
# reverses the body, which is a quiet way to ship scrambled release notes.
notes="$(awk -v want="## ${version}" '
	$0 == want { found = 1; next }
	found && /^## / { exit }
	found && /^[[:space:]]*$/ { if (started) pending = pending "\n"; next }
	found { printf "%s%s\n", pending, $0; pending = ""; started = 1 }
' "${changelog}")"

if [ -z "${notes}" ]; then
	echo "no section '## ${version}' in ${changelog}" >&2
	exit 1
fi

printf '%s\n' "${notes}"
