#!/bin/sh

# Run a scheduled command from the project directory and record its result.
# KURA_METRICS_DIR is overridable so the wrapper can be tested without the VM.
set -u

# Only simple names are allowed in file paths and Prometheus labels.
job_name=${1:-}
case "$job_name" in
    ''|*[!a-zA-Z0-9_-]*)
        echo "Invalid job name." >&2
        exit 2
        ;;
esac
shift
if [ "$#" -eq 0 ]; then
    echo "A command is required." >&2
    exit 2
fi

# The script lives two directories below the project root.
project_directory=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd) || exit 1
metrics_directory=${KURA_METRICS_DIR:-/var/lib/kura-metrics}
metrics_file="$metrics_directory/job_$job_name.prom"
mkdir -p "$metrics_directory" || exit 1
temporary_file=$(mktemp "$metrics_directory/.job_${job_name}.XXXXXX") || exit 1
trap 'rm -f -- "$temporary_file"' EXIT HUP INT TERM

# Run exactly the arguments provided; do not interpret them as shell code.
cd "$project_directory" || exit 1
"$@"
exit_code=$?

# Keep the previous success timestamp when the latest run fails.
if [ "$exit_code" -eq 0 ]; then
    printf 'kura_job_last_success_timestamp_seconds{job="%s"} %s\n' "$job_name" "$(date +%s)" > "$temporary_file"
elif [ -f "$metrics_file" ]; then
    grep -F "kura_job_last_success_timestamp_seconds{job=\"$job_name\"}" "$metrics_file" > "$temporary_file" || :
fi

# Replace the metrics file atomically, so scrapers never read half a file.
printf 'kura_job_last_exit_code{job="%s"} %s\n' "$job_name" "$exit_code" >> "$temporary_file"
# mktemp creates owner-only files; Alloy runs as another user and must be able
# to read them (they hold only job names, times and exit codes, nothing secret).
chmod 0644 "$temporary_file" || exit 1
mv -f -- "$temporary_file" "$metrics_file" || exit 1
exit "$exit_code"
