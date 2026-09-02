savedcmd_a2tp.mod := printf '%s\n'   a2tp_main.o a2tp_core.o a2tp_srv.o a2tp_netdev.o | awk '!x[$$0]++ { print("./"$$0) }' > a2tp.mod
