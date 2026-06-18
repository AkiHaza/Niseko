DEBUG=false

MODDIR=${0%/*}

cd $MODDIR

while true; do
  ./daemon "$MODDIR" || exit 1
  # ensure keystore initialized
  sleep 2
done &

# Clear logd size persist properties once boot completes
(
  until [ "$(getprop sys.boot_completed)" = "1" ]; do
    sleep 1
  done
  setprop persist.logd.size ""
  setprop persist.logd.size.crash ""
  setprop persist.logd.size.system ""
  setprop persist.logd.size.main ""
) &
