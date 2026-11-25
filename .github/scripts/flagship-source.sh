# Sourced by fetch-flagship-corpus.sh. A push names its monorepo commit in the head commit's message ("source <sha>").
# source_of <dir> [rev]: that sha for <rev> (default HEAD), empty when none.
# safe.directory: container jobs check out as another user, and git then refuses to read the repo (exit 128)
source_of() { { git -c safe.directory='*' -C "$1" log -1 --format=%B "${2:-HEAD}" -- 2>/dev/null || true; } | sed -n 's/^source \([0-9a-f]\{40\}\)$/\1/p' | tail -1; }
# find_source_commit <dir> <want>: the newest commit in the last 50 of <dir>'s first-parent history whose source is exactly <want>
# (so a later push of only some repos to the same branch does not strand runs of the others); prints nothing when there is none.
find_source_commit() {
  local c
  for c in $(git -c safe.directory='*' -C "$1" rev-list --first-parent -n 50 HEAD 2>/dev/null); do
    [ "$(source_of "$1" "$c")" = "$2" ] && { echo "$c"; return 0; }
  done
  return 0
}
