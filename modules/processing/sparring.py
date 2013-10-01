# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import re
import socket
import logging
import pickle
from urlparse import urlunparse

from lib.cuckoo.common.utils import convert_to_printable
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.dns import resolve
from lib.cuckoo.common.irc import ircMessage
from lib.cuckoo.common.objects import File

class Sparring:
    """Parse sparring analysis results. """

    def __init__(self, file_path):
        """Creates a new instance.
        @param filepath: path to sparring log file
        """
        self.filepath = file_path

        # List containing all IP addresses involved in the analysis.
        self.unique_hosts = []
        # List of unique domains.
        self.unique_domains = []
        # List containing all TCP packets.
        self.tcp_connections = []
        # List containing all UDP packets.
        self.udp_connections = []
        # List containing all HTTP requests.
        self.http_requests = []
        # List containing all DNS requests.
        self.dns_requests = []
        # List containing all SMTP requests.
        self.smtp_requests = []
        # Reconstruncted SMTP flow.
        self.smtp_flow = {}
        # List containing all IRC requests.
        self.irc_requests = []
        # Dictionary containing all the results of this processing.
        self.results = {}

    def _add_hosts(self, connection):
        """Add IPs to unique list.
        @param connection: connection data
        """
        try:
            if connection["src"] not in self.unique_hosts:
                self.unique_hosts.append(convert_to_printable(connection["src"]))
            if connection["dst"] not in self.unique_hosts:
                self.unique_hosts.append(convert_to_printable(connection["dst"]))
        except Exception:
            return False

        return True

    def _dns_gethostbyname(self, name):
        """Get host by name wrapper.
        @param name: hostname.
        @return: IP address or blank
        """
        if Config().processing.resolve_dns:
            ip = resolve(name)
        else:
            ip = ""
        return ip

    def _add_domain(self, domain):
        """Add a domain to unique list.
        @param domain: domain name.
        """
        filters = [
            ".*\\.windows\\.com$",
            ".*\\.in\\-addr\\.arpa$"
        ]

        regexps = [re.compile(filter) for filter in filters]
        for regexp in regexps:
            if regexp.match(domain):
                return

        for entry in self.unique_domains:
            if entry["domain"] == domain:
                return

        self.unique_domains.append({"domain" : domain,
                                    "ip" : self._dns_gethostbyname(domain)})

    def _check_http(self, tcpdata):
        """Checks for HTTP traffic.
        @param tcpdata: TCP data flow.
        """
        try:
            r = dpkt.http.Request()
            r.method, r.version, r.uri = None, None, None
            r.unpack(tcpdata)
        except dpkt.dpkt.UnpackError:
            if r.method != None or r.version != None or r.uri != None:
                return True
            return False

        return True

    def _add_http(self, tcpdata, dport):
        """Adds an HTTP flow.
        @param tcpdata: TCP data flow.
        @param dport: destination port.
        """
        try:
            http = dpkt.http.Request()
            http.unpack(tcpdata)
        except dpkt.dpkt.UnpackError:
            pass

        try:
            entry = {}

            if "host" in http.headers:
                entry["host"] = convert_to_printable(http.headers["host"])
            else:
                entry["host"] = ""

            entry["port"] = dport
            entry["data"] = convert_to_printable(tcpdata)
            entry["uri"] = convert_to_printable(urlunparse(("http", entry["host"], http.uri, None, None, None)))
            entry["body"] = convert_to_printable(http.body)
            entry["path"] = convert_to_printable(http.uri)

            if "user-agent" in http.headers:
                entry["user-agent"] = convert_to_printable(http.headers["user-agent"])

            entry["version"] = convert_to_printable(http.version)
            entry["method"] = convert_to_printable(http.method)

            self.http_requests.append(entry)
        except Exception:
            return False

        return True

    def _check_dns(self, udpdata):
        """Checks for DNS traffic.
        @param udpdata: UDP data flow.
        """
        try:
            dpkt.dns.DNS(udpdata)
        except:
            return False

        return True

    def _add_dns(self, udpdata):
        """Adds a DNS data flow.
        @param udpdata: UDP data flow.
        """
        dns = dpkt.dns.DNS(udpdata)

        # DNS query parsing.
        query = {}
 
        if dns.rcode == dpkt.dns.DNS_RCODE_NOERR or \
           dns.qr == dpkt.dns.DNS_R or \
           dns.opcode == dpkt.dns.DNS_QUERY or True:
            # DNS question.
            try:
                q_name = dns.qd[0].name
                q_type = dns.qd[0].type
            except IndexError:
                return False

            query["request"] = q_name
            if q_type == dpkt.dns.DNS_A:
                query["type"] = "A"
            if q_type == dpkt.dns.DNS_AAAA:    
                query["type"] = "AAAA"
            elif q_type == dpkt.dns.DNS_CNAME:
                query["type"] = "CNAME"
            elif q_type == dpkt.dns.DNS_MX:
                query["type"] = "MX"
            elif q_type == dpkt.dns.DNS_PTR:
                query["type"] = "PTR"
            elif q_type == dpkt.dns.DNS_NS:
                query["type"] = "NS"
            elif q_type == dpkt.dns.DNS_SOA:
                query["type"] = "SOA"
            elif q_type == dpkt.dns.DNS_HINFO:
                query["type"] = "HINFO"     
            elif q_type == dpkt.dns.DNS_TXT:
                query["type"] = "TXT"
            elif q_type == dpkt.dns.DNS_SRV:
                query["type"] = "SRV"

            # DNS answer.
            query["answers"] = []
            for answer in dns.an:
                ans = {}
                if answer.type == dpkt.dns.DNS_A:
                    ans["type"] = "A"
                    ans["data"] = socket.inet_ntoa(answer.rdata)
                elif answer.type == dpkt.dns.DNS_AAAA:
                    ans["type"] = "AAAA"
                    ans["data"] = socket.inet_ntop(socket.AF_INET6, answer.rdata)
                elif answer.type == dpkt.dns.DNS_CNAME:
                    ans["type"] = "CNAME"
                    ans["data"] = answer.cname
                elif answer.type == dpkt.dns.DNS_MX:
                    ans["type"] = "MX"
                    ans["data"] = answer.mxname
                elif answer.type == dpkt.dns.DNS_PTR:
                    ans["type"] = "PTR"
                    ans["data"] = answer.ptrname
                elif answer.type == dpkt.dns.DNS_NS:
                    ans["type"] = "NS"
                    ans["data"] = answer.nsname   
                elif answer.type == dpkt.dns.DNS_SOA:
                    ans["type"] = "SOA"
                    ans["data"] = ",".join(answer.mname,
                                           answer.rname,
                                           str(answer.serial),
                                           str(answer.refresh),
                                           str(answer.retry),
                                           str(answer.expire),
                                           str(answer.minimum)) 
                elif answer.type == dpkt.dns.DNS_HINFO:
                    ans["type"] = "HINFO"
                    ans["data"] = " ".join(answer.text)             
                elif answer.type == dpkt.dns.DNS_TXT:
                    ans["type"] = "TXT"
                    ans["data"] = " ".join(answer.text)

                # TODO: add srv handling
                query["answers"].append(ans)

            self._add_domain(query["request"])
            self.dns_requests.append(query)

        return True

    def _reassemble_smtp(self, conn, data):
        """Reassemble a SMTP flow.
        @param conn: connection dict.
        @param data: raw data.
        """
        if conn["dst"] in self.smtp_flow:
            self.smtp_flow[conn["dst"]] += data
        else:
            self.smtp_flow[conn["dst"]] = data

    def _process_smtp(self):
        """Process SMTP flow."""
        for conn, data in self.smtp_flow.iteritems():
            # Detect new SMTP flow.
            if data.startswith("EHLO") or data.startswith("HELO"):
                self.smtp_requests.append({"dst": conn, "raw": data})

    def _tcp_dissect(self, conn, data):
        """Runs all TCP dissectors.
        @param conn: connection.
        @param data: payload data.
        """
        if self._check_http(data):
            self._add_http(data, conn["dport"])
        # SMTP.
        if conn["dport"] == 25:
            self._reassemble_smtp(conn, data)
        # IRC.
        if self._check_irc(data):
            self._add_irc(data)

    def _udp_dissect(self, conn, data):
        """Runs all UDP dissectors.
        @param conn: connection.
        @param data: payload data.
        """
        if conn["dport"] == 53 or conn["sport"] == 53:
            if self._check_dns(data):
                self._add_dns(data)

    def _check_irc(self, tcpdata):
        """
        Checks for IRC traffic.
        @param tcpdata: tcp data flow
        """
        try:
            req = ircMessage()
        except Exception, why:
            return False

        return req.isthereIRC(tcpdata)

    def _add_irc(self, tcpdata):
        """
        Adds an IRC communication.
        @param tcpdata: TCP data in flow
        @param dport: destination port
        """

        try:
            reqc = ircMessage()
            reqs = ircMessage()
            filters_sc = ["266"]
            filters_cc = []
            self.irc_requests = self.irc_requests + reqc.getClientMessages(tcpdata) + reqs.getServerMessagesFilter(tcpdata,filters_sc)
        except Exception, why:
            return False

        return True

    def run(self):
        """Process Sparring log.
        @return: dict with network analysis data.
        """
        log = logging.getLogger("Processing.Sparring")

        if not os.path.exists(self.file_path):
            log.warning("The Sparring log file does not exist at path \"%s\"." % self.file_path)
            return None

        if os.path.getsize(self.file_path) == 0:
            log.error("The Sparring log file at path \"%s\" is empty." % self.file_path)
            return None

        try:
            file = open(self.file_path, "rb")
        except (IOError, OSError):
            log.error("Unable to open %s" % self.file_path)
            return None

        slog = pickle.load(file)

        file.close()

        # Build results dict.
        # TODO ... vvvvvvv ...
        # for i in slog,keys():
        #   ...
        self.results["hosts"] = self.unique_hosts
        self.results["domains"] = self.unique_domains
        self.results["tcp"] = self.tcp_connections
        self.results["udp"] = self.udp_connections
        self.results["http"] = self.http_requests
        self.results["dns"] = self.dns_requests
        self.results["smtp"] = self.smtp_requests
        self.results["irc"] = self.irc_requests

        return self.results

class SparringNetworkAnalysis(Processing):
    """Sparring supported network analysis."""

    def run(self):
        self.key = "sparring"
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task.id), "sparring.log")

        results = Sparring(file_path).run()

        return results
