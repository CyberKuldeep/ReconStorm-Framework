#!/bin/bash
# =============================================================
#  ReconStorm — Logger Library
#  Source this in all scripts: source lib/logger.sh
# =============================================================

# ANSI color codes (disabled if not a terminal)
if [[ -t 1 ]]; then
    _R='\033[0;31m' _G='\033[0;32m' _Y='\033[0;33m'
    _B='\033[0;34m' _C='\033[0;36m' _W='\033[0;37m' _N='\033[0m'
else
    _R='' _G='' _Y='' _B='' _C='' _W='' _N=''
fi

_ts() { date '+%H:%M:%S'; }

log_info()  { echo -e "${_C}[$(_ts)] [INFO]${_N}  $*"; }
log_ok()    { echo -e "${_G}[$(_ts)] [ OK ]${_N}  $*"; }
log_warn()  { echo -e "${_Y}[$(_ts)] [WARN]${_N}  $*"; }
log_error() { echo -e "${_R}[$(_ts)] [ERR ]${_N}  $*" >&2; }
log_debug() { [[ "${DEBUG:-0}" == "1" ]] && echo -e "${_W}[$(_ts)] [DBG ]${_N}  $*"; }
log_step()  { echo -e "${_B}[$(_ts)] [>>>]${_N}  $*"; }
