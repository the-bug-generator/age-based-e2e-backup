#!/bin/bash

set -Eeuo pipefail

# log error and exit
xerror() {
    echo "$@" >&2
    exit 1
}
export -f xerror

# encode file name so that it's not too obvious you're uploading copyrighted data
# encoding does not provide any kind of security, it just messes with hypothetical scanners on the cloud provider
enc_path() {
    local path dir file file_no_ext file_ext
    path="$1"
    if grep -q '/' <<<"$path"
    then
        dir="$( dirname -- "$path" )/"
    else
        dir=""
    fi
    file="$( basename -- "$path" )"
    if grep -F -q '.' <<<"$file"
    then
        file_no_ext="${file%.*}"
        file_ext="${file##*.}"
        echo "$dir$( base64 -w0 <<<"$file_no_ext" | tr '/' '-' ).$file_ext"
    else
        echo "$dir$( base64 -w0 <<<"$file" | tr '/' '-' )"
    fi
}
export -f enc_path

# decodes file name as encoded by enc_path
dec_path() {
    local path dir file file_no_ext file_ext
    path="$1"
    dir="$( dirname -- "$path" )"
    file="$( basename -- "$path" )"
    if grep -F -q '.' <<<"$file"
    then
        file_no_ext="${file%.*}"
        file_ext="${file##*.}"
        echo "$dir/$( tr '-' '/' <<<"$file_no_ext" | base64 -d ).$file_ext"
    else
        echo "$dir/$( tr '-' '/' <<<"$file" | base64 -d )"
    fi
}
export -f dec_path

# invokes a function and formats output based on return code so that logger can display nice stats
wrapped() {

    set -Eeuo pipefail

    local act decode_name enc_name in rel err rc

    act="$1"
    shift

    decode_name=0

    in="$1"
    if [ "$in" = "-d" ]
    then
        decode_name=1
        shift
        in="$1"
    fi

    rel="${in:$len_path_from}"
    if (( decode_name == 1 ))
    then
        rel="$( dec_path "$rel" )"
    fi

    enc_name="$( base64 -w0 <<<"${rel:1}" )"

    echo "start $enc_name"

    rc=0
    err="$( $act "$@" 2>&1 )" || rc="$?"
    case "$rc" in
        40) echo "ok_changed $enc_name";;
        41) echo "ok_new $enc_name";;
        42) echo "ok_done $enc_name";;
        50) echo "skipped_inc $enc_name";;
        51) echo "skipped_exc $enc_name";;
        52) echo "skipped_unchanged $enc_name";;
        *) echo "error $enc_name $( base64 -w0 <<<"rc=$rc -> $err" )";;
    esac

    echo "end $( base64 -w0 <<<"${rel:1}" )"
}
export -f wrapped

# actual age encryption
encrypt() {
    local in rel out out_dir dest_name out_meta m_key cur_meta
    in="$1"
    rel="${in:$len_path_from}"

    if [ "$regex_include" != "-" ]
    then
        grep -E "$regex_include" <<<"$in" >/dev/null || return 50
    fi
    if [ "$regex_exclude" != "-" ]
    then
        grep -E "$regex_exclude" <<<"$in" >/dev/null && return 51
    fi

    out_dir="$( dirname -- "$path_to$rel" )"
    [ -d "$out_dir" ] || mkdir -p "$out_dir"

    dest_name="$( enc_path "$( basename -- "$in" )" )"

    out="$out_dir/$dest_name"
    out_meta="$out_dir/.esync-meta.$dest_name"

    m_key="$( stat -c %s-%Y "$in" )"
    if [ -f "$out_meta" ]
    then
        read cur_meta <"$out_meta"
        if [ "$cur_meta" = "$m_key" ]
        then
            return 52
        else
            cat "$in" | age -r "$pub_key" >"$out" || xerror "Failed to encrypt"
            echo -n "$m_key" >"$out_meta" || xerror "Failed to store meta"
            return 40
        fi
    else
        cat "$in" | age -r "$pub_key" >"$out" || xerror "Failed to encrypt"
        echo -n "$m_key" >"$out_meta" || xerror "Failed to store meta"
        return 41
    fi
}
export -f encrypt

# actual age decryption
decrypt() {
    local in rel out_dir enc_name dest_name
    in="$1"
    rel="${in:$len_path_from}"

    out_dir="$( dirname -- "$path_to$rel" )"
    [ -d "$out_dir" ] || mkdir -p "$out_dir"

    enc_name="$( basename -- "$in")"
    dest_name="$( dec_path "$enc_name" )"

    age --decrypt -i "$path_key" -o "$out_dir/$dest_name" "$in" || xerror "Failed to decrypt"

    return 42
}
export -f decrypt

# sha2 check of encrypted files integrity (does not check exhaustivity, rerun --sync for that)
check() {
    local in rel out_dir enc_name dest_name backup_hash orig_hash
    in="$1"
    rel="${in:$len_path_from}"

    out_dir="$( dirname -- "$path_to$rel" )"

    enc_name="$( basename -- "$in")"
    dest_name="$( dec_path "$enc_name" )"

    backup_hash="$( age --decrypt -i "$path_key" "$in" | sha256sum | cut -d' ' -f1 )"
    orig_hash="$( cat "$out_dir/$dest_name" | sha256sum | cut -d' ' -f1 )"

    if [ "$backup_hash" = "$orig_hash" ]
    then
        return 42
    fi
    xerror "Hash mismatch"
}
export -f check

# nice output
log() {
    local start now elapsed statuses_counts statuses_log c total speed last_log in_progress errors l la path_new path_changed
    start="$( date +%s )"
    last_log=$start

    clear

    declare -A in_progress; in_progress=()
    declare -A statuses_counts; statuses_counts=()
    declare -A errors; errors=()
    declare -a path_new; path_new=()
    declare -a path_changed; path_changed=()
    echo -e '\x1B7'
    while read -r l
    do
        readarray -t -d' ' la <<<"$l"
        case "${la[0]}" in
            ok_changed) c="${statuses_counts["Changed"]:-0}"; statuses_counts["Changed"]="$(( c + 1 ))" || :; path_changed+=( "${la[1]}" ) || :;;
            ok_new) c="${statuses_counts["New"]:-0}"; statuses_counts["New"]="$(( c + 1 ))" || :; path_new+=( "${la[1]}" ) || :;;
            ok_done) c="${statuses_counts["Done"]:-0}"; statuses_counts["Done"]="$(( c + 1 ))" || :;;
            skipped_inc) c="${statuses_counts["Skipped (inc pattern mismatch)"]:-0}"; statuses_counts["Skipped (inc pattern mismatch)"]="$(( c + 1 ))" || :;;
            skipped_exc) c="${statuses_counts["Skipped (exc pattern match)"]:-0}"; statuses_counts["Skipped (exc pattern match)"]="$(( c + 1 ))" || :;;
            skipped_unchanged) c="${statuses_counts["Skipped (unchanged)"]:-0}"; statuses_counts["Skipped (unchanged)"]="$(( c + 1 ))" || :;;
            start) in_progress["$( base64 -d <<<"${la[1]}" )"]=1;;
            end) unset in_progress["$( base64 -d <<<"${la[1]}" )"] || :;;
            error)
                errors["$( base64 -d <<<"${la[1]}" )"]="$( base64 -d <<<"${la[2]}" )"
                c="${statuses_counts["Error"]:-0}"
                statuses_counts["Error"]="$(( c + 1 ))" || :
                ;;
        esac
        now="$( date +%s )"
        elapsed=$(( now - start )) || :
        if (( elapsed > 0 )) && (( ( now - last_log ) > 0 ))
        then
            total=0
            statuses_log=""
            for l in "${!statuses_counts[@]}"
            do
                (( total += statuses_counts["$l"] )) || :
                if [ -n "${statuses_log:-}" ]
                then
                    statuses_log="$statuses_log; "
                fi
                statuses_log="$statuses_log$l: ${statuses_counts["$l"]}"
            done
            speed="$( bc <<<"scale=3; $total / $elapsed" )"
            echo -e '\x1B[?25l\x1B8\x1B[0J'
            echo "Analyzed $total items in $elapsed S ($speed items/S) ($statuses_log)"
            if [ "${#in_progress[@]}" -gt 0 ]
            then
                echo "Currently processing: "
                sort -u < <(
                    for p in "${!in_progress[@]}"
                    do
                        echo "  - $p"
                    done
                )
            fi
            if [ "${#errors[@]}" -gt 0 ]
            then
                echo "Error: "
                sort -u < <(
                    for p in "${!errors[@]}"
                    do
                        echo "  - $p: ${errors["$p"]}"
                    done
                )
            fi
            echo -e '\x1B[?25h'
            last_log=$now
        fi
    done


    total=0
    statuses_log=""
    for l in "${!statuses_counts[@]}"
    do
        (( total += statuses_counts["$l"] )) || :
        if [ -n "${statuses_log:-}" ]
        then
            statuses_log="$statuses_log; "
        fi
        statuses_log="$statuses_log$l: ${statuses_counts["$l"]}"
    done
    speed="$( bc <<<"scale=3; $total / $elapsed" )"
    echo -e '\x1B[?25l\x1B8\x1B[0J'

    echo "Complete"
    echo "Analyzed $total items in $elapsed S ($speed items/S) ($statuses_log)"
    if [ "${#errors[@]}" -gt 0 ]
    then
        echo "Error: "
        sort -u < <(
            for p in "${!errors[@]}"
            do
                echo "  - $p: ${errors["$p"]}"
            done
        )
    fi
    echo -e '\x1B[?25h'
    echo "New items:"
    if [ "${#path_new[@]}" -gt 0 ]
    then
        sort -u < <(
            for p in "${path_new[@]}"
            do
                echo "  - $( base64 -d <<<"$p" )"
            done
        )
    fi
    echo "Changed items:"
    if [ "${#path_changed[@]}" -gt 0 ]
    then
        sort -u < <(
            for p in "${path_changed[@]}"
            do
                echo "  - $( base64 -d <<<"$p" )"
            done
        )
    fi
}

# do I need to say it
help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  -s, --sync
      Incremental E2E backup of SRC_PATH to DEST_PATH
  -r, --restore
      Restores encrypted files from SRC_PATH to DEST_PATH
  -c, --check
      Checks that files in backup are OK, by comparing sha2 hash of encrypted files from SRC_PATH with sha2 hash of cleartext files from DEST_PATH
  -i, --init
      Initializes a new age key pair for encryption/decryption.
      Store the keys securely, as backups will be useless if lost.
  -f, --from SRC_PATH
      Specifies the source directory for sync, restore or check.
  -t, --to DEST_PATH
      Specifies the destination directory for sync, restore or check.
  -k, --key KEY_PATH
      Specifies the path to the age key file.
  -T, --threads NUM
      Specifies the number of threads to use for processing (default: 3).
  -I, --include REGEX
      Specifies a regex pattern for files to include (see grep -E documentation).
  -X, --exclude REGEX
      Specifies a regex pattern for files to exclude (see grep -E documentation).

Examples:
  $0 -s -f /path/to/source -t /path/to/destination -k /path/to/keyfile -T 4
  $0 -r -f /path/to/source -t /path/to/destination -k /path/to/keyfile -T 4
  $0 -c -f /path/to/source -t /path/to/destination -k /path/to/keyfile -T 4
  $0 -i

EOF
    exit 1
}

if ! which age &>/dev/null
then
    xerror "age is not installed (sudo apt install age)"
fi

mode=-
path_from=-
path_to=-
path_key=-
regex_include=-
regex_exclude=-
threads=3
debug=0
while [ -n "${1:-}" ]
do
    case "${1:-}" in
        -d|--debug) debug=1;;
        -s|--sync) mode=s;;
        -r|--restore) mode=r;;
        -c|--check) mode=c;;
        -i|--init) mode=i;;
        -f|--from) shift; path_from=$1;;
        -t|--to) shift; path_to="$1";;
        -k|--key) shift; path_key="$1";;
        -T|--threads) shift; threads="$1";;
        -I|--include) shift; regex_include="$1";;
        -X|--exclude) shift; regex_exclude="$1";;
        *) xerror "Unknown parameter $1";;
    esac
    shift
done

if [ "$mode" = "-" ]
then
    echo "No mode specified" >&2
    help
elif [ "$mode" = "i" ]
then
    if [ -f pcloud-sync-key.txt ]
    then
        rm -f pcloud-sync-key.txt
    fi
    age-keygen -o pcloud-sync-key.txt
    echo "The public key above and the associated secret key stored in $( realpath pcloud-sync-key.txt ) have been generated"
    echo "Store them (very) securely as encrypted backups will become useless if you lose them"
elif [ "$mode" = "s" ] || [ "$mode" = "r" ] || [ "$mode" = "c" ]
then


    if [ "$path_from" = "-" ] || [ ! -d "$path_from" ]
    then
        xerror "invalid path $path_from"
    fi

    if [ "$path_to" = "-" ] || [ ! -d "$path_to" ]
    then
        xerror "invalid path $path_to"
    fi

    if [ ! -f "$path_key" ]
    then
        xerror "invalid path $path_key"
    fi

    path_from="$( realpath "$path_from" )"
    len_path_from="${#path_from}"
    path_to="$( realpath "$path_to" )"
    len_path_to="${#path_to}"

    pub_key="$( grep '^# public key:' "$path_key" | cut -d' ' -f4 )"

    export path_from path_to path_key len_path_from len_path_to pub_key regex_include regex_exclude

    if [ "$mode" = "s" ]
    then
        act=encrypt
    elif [ "$mode" = "r" ]
    then
        act="decrypt -d"
    else
        act="check -d"
    fi

    log=cat
    if (( debug == 0 ))
    then
        log=log
    fi

    tput init

    find "$path_from" -type f -not -name ".esync-meta.*" -print0 | xargs -0 -i -P $threads bash -c "wrapped $act \"\$1\"" . '{}' | $log
else
    echo "Invalid mode specified" >&2
    help
fi
