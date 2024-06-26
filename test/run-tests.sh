cd "$(dirname $0)"

LD_LIBRARY_PATH="../"
export LD_LIBRARY_PATH

/opt/circonus/bin/mtevbusted $@
