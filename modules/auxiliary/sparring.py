# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import stat
import getpass
import logging
import subprocess

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_GUEST_PORT
from lib.cuckoo.common.config import Config

log = logging.getLogger(__name__)

class Sparring(Auxiliary):
# TODO -h/-f/-t ueberschreiben lassen durch submit.py
#        if self.cfg.sparring.enabled:
#          try:
#            opts = dict(item.split("=") for item in self.task.custom.split(" "))
#          except:
#            opts = {}
#          sparring_mode = opts.get('sparring_mode', 't')
#
#          print 'have to start %s/sparring.py -a %s -%s' % (self.cfg.sparring.path, machine.ip, sparring_mode)
#            

    def start(self):
        sparring = self.options.get("path", "/usr/bin/sparring")
        print sparring
        ip = self.machine.ip

        # call submit.py like:
        # utils/submit.py --custom sparring_mode=transparent somefile
        try:
          opts = dict(item.split("=") for item in self.task.custom.split(" "))
          mode = opts.get('sparring_mode')
        except:
          mode = self.options.get("mode", "transparent")

        if mode == 'transparent':
          mode_opt= "-t"
        if mode == 'half':
          mode_opt= "-h"
        if mode == 'full':
          mode_opt= "-f"

        # Note:
        # You have to make sure that your iptables setup conforms to
        # the rules described for transparent and half/full mode:

        # use the ip addresses's last octet value as unique (nf)queue number in
        # transparent mode
        queueno = ip.split(".")[3]
        # similarly for our ports in half and full mode:
        port = "5" + queueno 

        if not os.path.exists(sparring):
            log.error("sparring does not exist at path \"%s\", network capture aborted", sparring)
            return

        # for now we use sudo to acquire the necessary rights to run sparring
        pargs = ["sudo", sparring, mode_opt, "-a", ip, "-p", port]

        try:
            # sudo sparring -a 123.0.0.1 -f -p 5002
            self.proc = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            pass
        except (OSError, ValueError) as e:
            log.exception("Failed to start sparring (host=%s, mode=%s)", ip, mode_opt)
            return

        log.info("Started sniffer (host=%s, mode=%s)", ip, mode)

    def stop(self):
        """Stop sniffing.
        @return: operation status.
        """
        if self.proc and not self.proc.poll():
            try:
                self.proc.terminate()
                print self.proc.communicate()
                # INSERT PICKLE-code to (de)serialize results from sparring
                # into processing/sparring.py
            except:
                try:
                    if not self.proc.poll():
                        log.debug("Killing sniffer")
                        self.proc.kill()
                except OSError as e:
                    log.debug("Error killing sniffer: %s. Continue", e)
                    pass
                except Exception as e:
                    log.exception("Unable to stop the sniffer with pid %d", self.proc.pid)
