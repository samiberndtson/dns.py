import sys
import argparse
import re
import sqlite3
import logging
import socket
import ssl
from urllib import parse
import http.client
import json
from itertools import zip_longest
import time
import ipaddress

COMMON_DOMAINS = ['*']

# Web
COMMON_DOMAINS += ['www', 'web', 'ws', 'm', 'mobile', 'webserver']

# Sub-sites
COMMON_DOMAINS += ['start', 'blog', 'info', 'news', 'forum', 'status', 'developers', 'devs', 'b2b', 'b2c', 'search', 'resources', 'feedback', 'enterprise']

# Support
COMMON_DOMAINS += ['support', 'help', 'helpdesk']

# Administration
COMMON_DOMAINS += ['staff', 'internal', 'admin', 'administration', 'sysadmin', 'webadmin', 'controlpanel', 'cp', 'backend']

# Authentication
COMMON_DOMAINS += ['auth', 'sso', 'saml', 'saml2', 'oauth', 'oauth2', 'login',  'signup']

# Ads and tracking
COMMON_DOMAINS += ['ads', 'ad', 'tracking', 'tracker', 'pixel', 'campaign', 'marketing', 'promo', 'promotion', 'clicks', 'survey']

# User statistics
COMMON_DOMAINS += ['backend', 'server', 'host']

# User statistics
COMMON_DOMAINS += ['matomo', 'posthog', 'analytics', 'statistics', 'stats']

# Images and assets
COMMON_DOMAINS += ['images', 'imgs', 'img', 'pictures', 'media', 'assets', 'css', 'js', 'javascript', 'static']

# Video and streaming
COMMON_DOMAINS += ['stream', 'streaming', 'video', 'tv', 'play', 'player']

# Testing and development
COMMON_DOMAINS += ['fake', 'live', 'new', 'old', 'alpha', 'beta', 'staging', 'stage', 'prod', 'production', 'test', 'testing', 'dev', 'development', 'demo', 'preview', 'sandbox', 'legacy', 'lab', 'experimentation', 'experiment', 'deprecated', 'v2']

# Membership
COMMON_DOMAINS += ['members', 'member', 'community', 'subscribe', 'premium', 'account', 'accounts', 'try', 'my', 'connect', 'register']

# API
COMMON_DOMAINS += ['api', 'graphql', 'callbacks', 'webhooks']

# CMS
COMMON_DOMAINS += ['cms', 'wordpress', 'wp', 'drupal', 'joomla', 'umbraco', 'squarespace', 'episerver', 'epi', 'shopify', 'magento']

# Cpanel
COMMON_DOMAINS += ['cpanel', 'whm']

# Mail
COMMON_DOMAINS += ['mail', 'mail2', 'email', 'smtp', 'pop', 'imap', 'webmail', 'newsletter', 'autodiscover', 'exchange', 'mailserver', 'mx']

# E-commerce and payments
COMMON_DOMAINS += ['shop', 'store', 'pay', 'payments', 'billing', 'cart', 'order']

# Source code
COMMON_DOMAINS += ['source', 'git', 'gitlab', 'hg', 'mercurial', 'bitbucket', 'svn', 'code', 'repo', 'repository', 'redmine']

# Monitoring
COMMON_DOMAINS += ['elastic', 'elasticsearch', 'grafana', 'icinga', 'nagios', 'logs', 'log', 'monitor', 'monitoring', 'observer', 'snmp', 'health', 'dashboard']

# Documentation
COMMON_DOMAINS += ['intranet', 'portal', 'wiki', 'mediawiki', 'docs', 'doc', 'documentation', 'confluence', 'pastebin', 'kb', 'knowledgebase', 'jira']

# Files
COMMON_DOMAINS += ['storage', 'files', 'filetransfer', 'transfer', 'downloads', 'download', 'upload', 'uploads', 'assets', 'static', 'backup', 'backups', 'smb', 'nfs', 'ftp', 'sftp', 'owncloud', 'nextcloud', 'webdisk', 'share', 'cdn', 'get', 'updates', 'update']

# Database
COMMON_DOMAINS += ['database', 'db', 'mysql', 'sql', 'postgres', 'pg', 'maria', 'mariadb', 'mongo', 'mongodb', 'mssql', 'master', 'slave', 'primary', 'secondary', 'phpmyadmin']

# Caching
COMMON_DOMAINS += ['redis', 'memcache', 'varnish', 'cache', 'caching', 'mirror']

# Work
COMMON_DOMAINS += ['jobs', 'career', 'work', 'hr']

# Investor
COMMON_DOMAINS += ['investor', 'investors', 'ir']

# Cloud
COMMON_DOMAINS += ['gcp', 'azure', 'aws', 'heroku', 'cloudflare']

# Redirects
COMMON_DOMAINS += ['next', 'links', 'link', 'redirect', 'go', 'forward', 'connect', 'share']

# Physical network
COMMON_DOMAINS += ['wifi', 'ap', 'accesspoint', 'switch', 'router', 'netbox', 'ns', 'ns1', 'ns2', 'gw', 'gateway', 'ldap']

# Office
COMMON_DOMAINS += ['office', 'workplace', 'locale']

# Country
COMMON_DOMAINS += ['us', 'uk', 'ca', 'fr', 'de', 'es', 'pt', 'it', 'se', 'no', 'dk', 'fi', 'jp', 'in']

# Managment
COMMON_DOMAINS += ['telnet', 'ssh', 'vnc', 'rdp', 'manage', 'management', 'mgmt', 'remote', 'console', 'mdm', 'adm']

# Tunneling and proxying
COMMON_DOMAINS += ['tunnel', 'proxy', 'vpn', 'squid', 'pptp', 'jump', 'jumpbox', 'jumphost']

# Certificates
COMMON_DOMAINS += ['ca', 'cert', 'certificate', 'acme', 'ssl', 'tls']

# Containers
COMMON_DOMAINS += ['registry', 'docker', 'k8s', 'kubernetes', 'cluster']

# Linux repos
COMMON_DOMAINS += ['apt', 'rpm', 'repo', 'deb', 'debian', 'ubuntu', 'redhat', 'centos']

# Chat
COMMON_DOMAINS += ['chat', 'irc', 'slack', 'mattermost', 'discuss']

# Phone
COMMON_DOMAINS += ['sip']

# Misc
COMMON_DOMAINS += ['hgfgdf', 'lkjkui', 'govyty', 'apps', 'app', 'feed', 'projects', 'project', 'open', 'explore', 'calendar', 'server', 'secure', 'host', 'cloud', 'tools', 'learn', 'elearning', 'training', 'webcam', 'it']



REVERSE_IPS = {}
DOMAINS = {}
TARGETS = []

# Check if domain is among targets
def in_targets(domain):

    for target in TARGETS:
        if domain[-(len(target) + 1):] == "."+target:
            return True

    return False

def domain_type(arg_value, pat=re.compile(r"^([a-z0-9-]+\.)+[a-z]{2,63}$")):
    if not pat.match(arg_value):
        raise argparse.ArgumentTypeError(arg_value)
    return arg_value

# Reverse IP lookup
def reverse_lookup(ip):

    if ip in REVERSE_IPS:
        return REVERSE_IPS[ip]

    try:
        domain_name = socket.gethostbyaddr(ip)
        REVERSE_IPS[ip] = domain_name[0]
        if in_targets(domain_name[0]):
            lookup(domain_name[0])
        return REVERSE_IPS[ip]
    except Exception:
        REVERSE_IPS[ip] = ""
        return None

# Resolve domain
def lookup(domain):

    if domain in DOMAINS:
        return DOMAINS[domain]

    try:
        #time.sleep(0.1)
        data = []
        addressInfo = socket.getaddrinfo(domain, 0, proto=socket.IPPROTO_TCP)
        for a in addressInfo:
            data.append(a[-1][0])

        #data = socket.gethostbyname_ex(domain)
        data.sort()

        #if not empty(data[1]):
        #    ipx = tuple((data[0],))
        #else:
        #    ipx = tuple(data[2])
        ipx = tuple(data)

        DOMAINS[domain] = ipx

        for ip in ipx:
            for i in range(-5,5):
                range_ip = str(ipaddress.ip_address(ip)+i)
                reverse_lookup(range_ip)

        get_ssl(domain)
        return ipx
    except Exception:
        DOMAINS[domain] = tuple()
        return ()

def get_ssl(domain):
    result = set()
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        ssl_sock = context.wrap_socket(s, server_hostname=domain)
        ssl_sock.connect((domain, 443))
        cert = ssl_sock.getpeercert()
        ssl_sock.close()
        for d in cert['subjectAltName']:
            if in_targets(d[1]):
                lookup(d[1])
        return list(result)
    except socket.error:
        return list(result)

def lookup_transparency_logs(domain):

    users = []
    headers = {
            "Accept": "application/json",
        }

    args = parse.urlencode({"q": domain, "output": "json"})
    conn = http.client.HTTPSConnection("crt.sh")
    conn.request("GET", "/?%s" % args, headers=headers)
    response = conn.getresponse()
    body =  response.read()

    data = json.loads(body)

    for entry in data:
        users.append(entry["common_name"])
        list = entry["name_value"].split("\n")
        for domain in list:
            lookup(domain)

    return users


def main():

    global TARGETS

    parser = argparse.ArgumentParser(description='Scan for sub-domains')
    parser.add_argument('domains', metavar='domain', type=domain_type, nargs='+', help='domains to scan')
    parser.add_argument('-k', metavar='known', type=domain_type, nargs='+', help='Known domains to include in result')
    args = parser.parse_args()

    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)

    TARGETS = [x for x in args.domains]

    for domain in args.k or []:
        lookup(domain)

    for domain in args.domains:

        lookup_transparency_logs(domain)

        for target in COMMON_DOMAINS:
            lookup("%s.%s" % (target, domain))


    wildcard_domains = []
    for key, value in DOMAINS.items():
        if key[0] == '*':
            wildcard_domains.append(value)

    v = {}

    for key, value in DOMAINS.items():
        if (key[0] != '*') and (value in wildcard_domains):
            continue
        v.setdefault(tuple(value), set()).add(key)

    for key, value in v.items():
        if not key:
            continue
        print("\n")
        for ip, l2 in zip_longest(key, value, fillvalue=None):
            reverse_ip = None
            ports = None
            if ip:
                reverse_ip = REVERSE_IPS[ip]
            print('{:<60}{:<30}{:<80}'.format(l2 or "", ip or "", reverse_ip or ""))


if __name__ == '__main__':
    sys.exit(main())