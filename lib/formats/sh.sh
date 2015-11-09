#!/bin/sh
# This file was autowritten by rmlint
# rmlint was executed from: %s
# Your command line was: %s

USER='%s'
GROUP='%s'

# Set according to S for option -n or D for option -d
CONFIRM=unset

# Set to true on -p
DO_PARANOID_CHECK=


####################
# INTERACTIVE MODE #
####################

set_delete_commands() {
    REMOVE_DUPE_CMD="rm -rf"
    REMOVE_EDIR_CMD="rmdir"
    REMOVE_OTHER_CMD="rm -f"
    DELETE_VERB="Deleting"
}

set_trash_commands() {
    if [ -z "$TRASH_CMD" ]
    then
     echo "Error: no trash command found"
     return 1
    fi
    REMOVE_DUPE_CMD=$TRASH_CMD
    REMOVE_EDIR_CMD=$TRASH_CMD
    REMOVE_OTHER_CMD=$TRASH_CMD
    DELETE_VERB="Trashing"
    return 0
}

confirm() {

    case $CONFIRM in
        [DT]) return 0
        ;;
        S) return 1
        ;;
    esac

    while :
    do
        echo "d: delete / D: delete all / t: trash / T: trash all / s: skip / S: skip all / A: abort?"
        read CONFIRM
        echo
        case $CONFIRM in
            [dD])
                set_delete_commands
                return 0
            ;;
            [tT])
                if set_trash_commands
                then
                    return 0
                fi
            ;;
            [sS])
                return 1
            ;;
            A)
                exit 1
            ;;
            *)
                echo "Option not recognised"
            ;;
        esac
    done
}


##################################
# GENERAL LINT HANDLER FUNCTIONS #
##################################


handle_emptyfile() {
    echo "$DELETE_VERB empty file:" "$1"
    if confirm; then
        $REMOVE_OTHER_CMD "$1"
    fi
}

handle_emptydir() {
    echo "$DELETE_VERB empty directory:" "$1"
    if confirm; then
        $REMOVE_EDIR_CMD "$1"
    fi
}

handle_bad_symlink() {
    echo "$DELETE_VERB symlink pointing nowhere:" "$1"
    if confirm; then
        $REMOVE_OTHER_CMD "$1"
    fi
}

handle_unstripped_binary() {
    echo "Stripping debug symbols of:" "$1"
    if [ "$CONFIRM" != "S" ]; then
        strip -s "$1"
    fi
}

handle_bad_user_id() {
    echo "chown" "$USER" "$1"
    if [ "$CONFIRM" != "S" ]; then
        chown "$USER" "$1"
    fi
}

handle_bad_group_id() {
    echo "chgrp" "$GROUP" "$1"
    if [ "$CONFIRM" != "S" ]; then
        chgrp "$GROUP" "$1"
    fi
}

handle_bad_user_and_group_id() {
    echo "chown" "$USER:$GROUP" "$1"
    if [ "$CONFIRM" != "S" ]; then
        chown "$USER:$GROUP" "$1"
    fi
}

###############################
# DUPLICATE HANDLER FUNCTIONS #
###############################

original_check() {
    if [ ! -e "$2" ]; then
        echo "^^^^^^ Error: original has disappeared - cancelling....."
        return 1
    fi

    if [ ! -e "$1" ]; then
        echo "^^^^^^ Error: duplicate has disappeared - cancelling....."
        return 1
    fi

    # Check they are not the exact same file (hardlinks allowed):
    if [ "$1" = "$2" ]; then
        echo "^^^^^^ Error: original and duplicate point to the *same* path - cancelling....."
        return 1
    fi

    # Do double-check if requested:
    if [ -z "$DO_PARANOID_CHECK" ]; then
        return 0
    else
        if cmp -s "$1" "$2"; then
            return 0
        else
            echo "^^^^^^ Error: files no longer identical - cancelling....."
            return 1
        fi
    fi
}

cp_hardlink() {
    echo "Hardlinking to original:" "$1"
    if original_check "$1" "$2"; then
        if [ "$CONFIRM" != "S" ]; then
            cp --remove-destination --archive --link "$2" "$1"
        fi
    fi
}

cp_symlink() {
    echo "Symlinking to original:" "$1"
    if original_check "$1" "$2"; then
        if [ "$CONFIRM" != "S" ]; then
            touch -mr "$1" "$0"
            cp --remove-destination --archive --symbolic-link "$2" "$1"
            touch -mr "$0" "$1"
        fi
    fi
}

cp_reflink() {
    # reflink $1 to $2's data, preserving $1's  mtime
    echo "Reflinking to original:" "$1"
    if original_check "$1" "$2"; then
        if [ "$CONFIRM" != "S" ]; then
            touch -mr "$1" "$0"
            cp --reflink=always "$2" "$1"
            touch -mr "$0" "$1"
        fi
    fi
}

clone() {
    # clone $1 from $2's data
    echo "Cloning to: " "$1"
    if [ "$CONFIRM" != "S" ]; then
        rmlint --btrfs-clone "$2" "$1"
    fi
}

skip_hardlink() {
    echo "Leaving as-is (already hardlinked to original):" "$1"
}

skip_reflink() {
    echo "Leaving as-is (already reflinked to original):" "$1"
}

user_command() {
    # You can define this function to do what you want:
    %s
}

remove_cmd() {
    echo "$DELETE_VERB:" "$1"
    if original_check "$1" "$2"; then
        if confirm; then
            $REMOVE_DUPE_CMD "$1"
        fi
    fi
}

##################
# OPTION PARSING #
##################

ask() {
    cat << EOF

This script will delete certain files rmlint found.
It is highly advisable to view the script first!

Rmlint was executed in the following way:

   $ %s

Execute this script with -d to bypass this message and delete found lint.
Type any string to continue; CTRL-C, Enter or CTRL-D to abort immediately
EOF
    read eof_check
    if [ -z "$eof_check" ]
    then
        # Count Ctrl-D and Enter as aborted too.
        echo "Aborted on behalf of the user."
        exit 1;
    fi
}

usage() {
    cat << EOF
usage: $0 OPTIONS

OPTIONS:

  -h   Show this message.
  -d   Delete (or otherwise process) all lint non-interactively.
  -t   Move files to trash instead of deleting (requires gvfs-trash or trash-cli)
  -x   Keep rmlint.sh; do not autodelete it.
  -p   Recheck that files are still identical before removing duplicates.
  -n   Do not perform any modifications, just print what would be done.
EOF
}

DO_REMOVE=
set_delete_commands
TRASH_CMD=
command -v gvfs-trash >/dev/null 2>&1 && { echo "found command gvfs-trash"; TRASH_CMD="gvfs-trash"; }
command -v trash-cli >/dev/null 2>&1 && { echo "found command trash-cli"; TRASH_CMD="trash-cli"; }

while getopts "dhxnpt" OPTION
do
  case $OPTION in
     h)
       usage
       exit 1
       ;;
     d)
       CONFIRM=D
       ;;
     x)
       DO_REMOVE=false
       ;;
     n)
       CONFIRM=S
       ;;
     p)
       DO_PARANOID_CHECK=true
       ;;
     t)
       if ! set_trash_commands
       then
           echo "Aborting"
           exit 1
       fi
       ;;
  esac
done

if [ -z $DO_ASK ]
then
  usage
  ask
fi

######### START OF AUTOGENERATED OUTPUT #########


