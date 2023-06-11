# Compile
```bash
gcc icmpflood.c -o icmpflood
```

# Help
```
usage: ./icmpflood [target] [flags]

arguments program:
  -h, -help             Show this help message and exit.
  -v, -verbose          On verbose mode.

arguments main:
  -delay <ms>           Edit delay before send.
  -count <count>        Set count send packets.
  -size <byte>          Set size send packets.
  -ttl <count>          Set TTL on IP header.

Created by lomaster & OldTeam
```

# Errors
```
Target only DNS or IP.
Max size arch linux: 1500.
Only sudo run!
```
