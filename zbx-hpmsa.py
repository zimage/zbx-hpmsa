#!/usr/bin/env python3

import os
import json
import urllib3
from hashlib import md5
from socket import gethostbyname
from argparse import ArgumentParser
from xml.etree import ElementTree as eTree
from datetime import datetime, timedelta

import sqlite3
import requests


def make_pwd_hash(cred, isfile=False):
    """
    The function makes md5 hash of login string.
    :param cred:
    str: Login string in 'user_password' format or path to the file with credentials.
    :param isfile:
    bool: Is string the file path.
    :return:
    str: md5 hash
    """

    if isfile:
        if os.path.exists(cred):
            with open(cred, 'r') as login_file:
                login_data = login_file.readline().replace('\n', '').strip()
                if login_data.find('_') != -1:
                    hashed = md5(login_data.encode()).hexdigest()
                else:
                    hashed = login_data
        else:
            raise SystemExit("ERROR: File password doesn't exists: {}".format(cred))
    else:
        hashed = md5(cred.encode()).hexdigest()
    return hashed


def prepare_tmp():
    """
    The function check access rights and existence of temporary dir.
    :return:
    str() Temporary disk path.
    """

    if os.name == 'posix':
        tmp_dir = '/dev/shm/zbx-hpmsa/'
        run_user = os.getenv('USER')
        if not os.path.exists(tmp_dir):
            os.makedirs(tmp_dir)
            os.chmod(tmp_dir, 0o770)
        elif not os.access(tmp_dir, 2):  # 2 - os.W_OK:
            raise SystemExit("ERROR: '{}' not writable for user '{}'.".format(tmp_dir, run_user))
    else:
        # Current dir. Yeap, it's easier than getcwd() or os.path.dirname(os.path.abspath(__file__)).
        tmp_dir = ''
    return tmp_dir


def sql_op(query, fetch_all=False):
    """
    The function works with SQL backend.
    :param query:
    str: SQL query to execute.
    :param fetch_all:
    bool: Set it True to execute fetchall().
    :return:
    None
    """

    if not any(verb.lower() in query.lower() for verb in ['DROP', 'DELETE', 'TRUNCATE', 'ALTER']):
        conn = sqlite3.connect(CACHE_DB)
        cursor = conn.cursor()
        try:
            if not fetch_all:
                data = cursor.execute(query).fetchone()
            else:
                data = cursor.execute(query).fetchall()
        except sqlite3.OperationalError as e:
            if str(e).startswith('no such table'):
                raise SystemExit("Cache is empty")
            else:
                raise SystemExit('ERROR: {}. Query: {}'.format(e, query))
        conn.commit()
        conn.close()
        return data
    else:
        raise SystemExit('ERROR: Unacceptable SQL query: "{query}"'.format(query=query))


def get_skey(storage, hashed_login, use_cache=True):
    """
    Get's session key from HP MSA API.
    :param storage:
    str: Storage IP address or DNS name.
    :param hashed_login:
    str: Hashed with md5 login data.
    :param use_cache:
    bool: The function will try to save session key to disk.
    :return:
    str: Session key or error code.
    """

    msa_ip = gethostbyname(storage)

    # Trying to use cached session key
    if use_cache:
        cur_timestamp = datetime.timestamp(datetime.utcnow())
        if not USE_HTTPS:  # http
            cache_data = sql_op('SELECT expired,skey FROM skey_cache WHERE ip="{}" AND proto="http"'.format(storage))
        else:  # https
            cache_data = sql_op('SELECT expired,skey '
                                'FROM skey_cache '
                                'WHERE dns_name="{}" AND IP ="{}" AND proto="https"'.format(storage, msa_ip))
        if cache_data is not None:
            cache_expired, cached_skey = cache_data
            if cur_timestamp < float(cache_expired):
                return cached_skey
            else:
                return get_skey(storage, hashed_login, use_cache=False)
        else:
            return get_skey(storage, hashed_login, use_cache=False)
    else:
        # Forming URL and trying to make GET query
        login_url = '{strg}/api/login/{hash}'.format(strg=storage, hash=hashed_login)
        return_code, sessionkey, xml_data = query_xmlapi(url=login_url, sessionkey=None)

        # 1 - success, write sessionkey to DB and return it
        if return_code == '1':
            expired_time = datetime.timestamp(datetime.utcnow() + timedelta(minutes=15))
            if not USE_HTTPS:  # http
                if sql_op('SELECT ip FROM skey_cache WHERE ip = "{}" AND proto="http"'.format(storage)) is None:
                    sql_op('INSERT INTO skey_cache VALUES ('
                           '"{dns}", "{ip}", "http", "{time}", "{skey}")'.format(dns=storage, ip=storage,
                                                                                 time=expired_time, skey=sessionkey))
                else:
                    sql_op('UPDATE skey_cache SET skey="{skey}", expired="{expired}" '
                           'WHERE ip="{ip}" AND proto="http"'.format(skey=sessionkey, expired=expired_time, ip=storage))
            else:  # https
                if sql_op('SELECT dns_name, ip FROM skey_cache '
                          'WHERE dns_name="{}" AND ip="{}" AND proto="https"'.format(storage, msa_ip)) is None:
                    sql_op('INSERT INTO skey_cache VALUES ('
                           '"{name}", "{ip}", "https", "{expired}", "{skey}")'.format(name=storage, ip=msa_ip,
                                                                                      expired=expired_time,
                                                                                      skey=sessionkey))
                else:
                    sql_op('UPDATE skey_cache SET skey = "{skey}", expired = "{expired}" '
                           'WHERE dns_name="{name}" AND ip="{ip}" AND proto="https"'.format(skey=sessionkey,
                                                                                            expired=expired_time,
                                                                                            name=storage, ip=msa_ip))
            return sessionkey
        # 2 - Authentication Unsuccessful, return "2"
        elif return_code == '2':
            return return_code


def query_xmlapi(url, sessionkey):
    """
    Making HTTP request to HP MSA XML API and returns it's response as 3-element tuple.
    :param url:
    str: URL to make GET request.
    :param sessionkey:
    str: Session key to authorize.
    :return:
    tuple: Tuple with str() return code, str() return description and etree object <xml.etree.ElementTree.Element>.
    """

    # Set file where we can find root CA
    ca_file = '/etc/ssl/certs/ca-bundle.crt'

    # Makes GET request to URL
    try:
        if not USE_HTTPS:  # http
            url = 'http://' + url
            response = requests.get(url, headers={'sessionKey': sessionkey})
        else:  # https
            url = 'https://' + url
            if VERIFY_SSL:
                response = requests.get(url, headers={'sessionKey': sessionkey}, verify=ca_file)
            else:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                response = requests.get(url, headers={'sessionKey': sessionkey}, verify=False)
    except requests.exceptions.SSLError:
        raise SystemExit('ERROR: Cannot verify storage SSL Certificate.')
    except requests.exceptions.ConnectionError:
        raise SystemExit("ERROR: Cannot connect to storage.")

    # Reading data from server XML response
    try:
        if args.savexml is not None and 'login' not in url:
            try:
                with open(args.savexml, 'w') as xml_file:
                    xml_file.write(response.text)
            except PermissionError:
                    raise SystemExit('ERROR: Cannot save XML file to "{}"'.format(args.savexml))
        response_xml = eTree.fromstring(response.content)
        return_code = response_xml.find("./OBJECT[@name='status']/PROPERTY[@name='return-code']").text
        return_response = response_xml.find("./OBJECT[@name='status']/PROPERTY[@name='response']").text

        return return_code, return_response, response_xml
    except (ValueError, AttributeError) as e:
        raise SystemExit("ERROR: Cannot parse XML. {}".format(e))


def get_health(storage, component, item, sessionkey):
    """
    The function gets single item of MSA component. E.g. - status of one disk.
    :param storage:
    str: Storage DNS name or it's IP address.
    :param sessionkey:
    str: Session key, which must be attach to the request header.
    :param component:
    str: Name of storage component, what we want to get - vdisks, disks, etc.
    :param item:
    str: ID number of getting component - number of disk, name of vdisk, etc.
    :return:
    str: HTTP response text.
    """

    if component in ('vdisks', 'disks'):
        get_url = '{strg}/api/show/{comp}/{item}'.format(strg=storage, comp=component, item=item)
    elif component in ('controllers', 'enclosures'):
        get_url = '{strg}/api/show/{comp}'.format(strg=storage, comp=component)
    else:
        raise SystemExit('ERROR: Wrong component "{}"'.format(component))

    resp_return_code, resp_description, resp_xml = query_xmlapi(get_url, sessionkey)
    if resp_return_code != '0':
        raise SystemExit('ERROR: {rc} : {rd}'.format(rc=resp_return_code, rd=resp_description))

    # Matching dict
    md = {'controllers': 'controller-id', 'enclosures': 'enclosure-id', 'vdisks': 'virtual-disk', 'disks': 'drive'}

    # Returns health statuses
    if component in ('vdisks', 'disks'):
        try:
            health = resp_xml.find("./OBJECT[@name='{}']/PROPERTY[@name='health']".format(md[component])).text
        except AttributeError:
            raise SystemExit("ERROR: No such id: '{}'".format(item))
    elif component in ('controllers', 'enclosures'):
        # we'll make dict {ctrl_id: health} because of we cannot call API for exact controller status
        health_dict = {}
        for ctrl in resp_xml.findall("./OBJECT[@name='{}']".format(component)):
            ctrl_id = ctrl.find("./PROPERTY[@name='{}']".format(md[component])).text
            health_dict[ctrl_id] = ctrl.find("./PROPERTY[@name='health']").text
        # If given item presents in our dict - return status
        if item in health_dict:
            health = health_dict[item]
        else:
            raise SystemExit("ERROR: No such id: '{}'.".format(item))
    else:
        raise SystemExit("ERROR: Wrong component '{}'".format(component))
    return health


def make_discovery(storage, component, sessionkey):
    """
    :param storage:
    str: Storage DNS name or it's IP address.
    :param sessionkey:
    str: Session key, which must be attach to the request header.
    :param component:
    str: Name of storage component, what we want to get - vdisks, disks, etc.
    :return:
    str: JSON with discovery data.
    """

    # Forming URL
    show_url = '{strg}/api/show/{comp}'.format(strg=storage, comp=component)

    # Making request to API
    resp_return_code, resp_description, xml = query_xmlapi(show_url, sessionkey)
    if resp_return_code != '0':
        raise SystemExit('ERROR: {rc} : {rd}'.format(rc=resp_return_code, rd=resp_description))

    # Eject XML from response
    if component is not None:
        all_components = []
        raw_json_part = ''
        if component.lower() == 'vdisks':
            for vdisk in xml.findall("./OBJECT[@name='virtual-disk']"):
                vdisk_name = vdisk.find("./PROPERTY[@name='name']").text
                vdisk_dict = {"{#VDISKNAME}": "{}".format(vdisk_name)}
                all_components.append(vdisk_dict)
        elif component.lower() == 'disks':
            for disk in xml.findall("./OBJECT[@name='drive']"):
                disk_loc = disk.find("./PROPERTY[@name='location']").text
                disk_sn = disk.find("./PROPERTY[@name='serial-number']").text
                disk_dict = {"{#DISKLOCATION}": "{}".format(disk_loc),
                             "{#DISKSN}": "{}".format(disk_sn)}
                all_components.append(disk_dict)
        elif component.lower() == 'controllers':
            for ctrl in xml.findall("./OBJECT[@name='controllers']"):
                ctrl_id = ctrl.find("./PROPERTY[@name='controller-id']").text
                ctrl_sn = ctrl.find("./PROPERTY[@name='serial-number']").text
                ctrl_ip = ctrl.find("./PROPERTY[@name='ip-address']").text
                # Find all possible ports
                # fc_ports = {}
                # for port in ctrl.findall("./OBJECT[@name='ports']"):
                #     port_name = port.find("./PROPERTY[@name='port']").text
                #     sfp_present = port.find(".//PROPERTY[@name='sfp-present-numeric']").text
                #     fc_ports[port_name] = sfp_present
                # for port, status in fc_ports.items():
                #     raw_json_part += '{{"{{#PORTNAME}}":"{}","{{#SFPPRESENT}}":"{}"}},'.format(port, status)
                # Forming final dict
                ctrl_dict = {"{#CTRLID}": "{}".format(ctrl_id),
                             "{#CTRLSN}": "{}".format(ctrl_sn),
                             "{#CTRLIP}": "{}".format(ctrl_ip)}
                all_components.append(ctrl_dict)
        elif component.lower() == 'enclosures':
            for encl in xml.findall("./OBJECT[@name='enclosures']"):
                encl_id = encl.find("./PROPERTY[@name='enclosure-id']").text
                encl_sn = encl.find("./PROPERTY[@name='midplane-serial-number']").text
                # all_ps = [PS.find("./PROPERTY[@name='durable-id']").text
                #           for PS in encl.findall("./OBJECT[@name='power-supplies']")]
                # for ps in all_ps:
                #     raw_json_part += '{{"{{#POWERSUPPLY}}":"{}"}},'.format(ps)
                # Forming final dict
                encl_dict = {"{#ENCLOSUREID}": "{}".format(encl_id),
                             "{#ENCLOSURESN}": "{}".format(encl_sn)}
                all_components.append(encl_dict)

        # Dumps JSON and return it
        if not raw_json_part:
            return json.dumps({"data": all_components}, separators=(',', ':'))
        else:
            return json.dumps({"data": all_components}, separators=(',', ':'))[:-2] + ',' + raw_json_part[:-1] + ']}'
    else:
        raise SystemExit('ERROR: You must provide the storage component (vdisks, disks, controllers, enclosures)')


def get_full_data(storage, component, sessionkey):
    """
    :param storage:
    str: Storage DNS name or it's IP address.
    :param sessionkey:
    str: Session key, which must be attach to the request header.
    :param component:
    str: Name of storage component, what we want to get - vdisks, disks, etc.
    :return:
    str: JSON with all found data. For example:
    """

    url = '{strg}/api/show/{comp}/'.format(strg=storage, comp=component)

    # Making request to API
    resp_return_code, resp_description, xml = query_xmlapi(url, sessionkey)
    if resp_return_code != '0':
        raise SystemExit('ERROR: {rc} : {rd}'.format(rc=resp_return_code, rd=resp_description))

    # Processing XML
    all_components = {}
    if component == 'disks':
        for PROP in xml.findall("./OBJECT[@name='drive']"):
            # Processing main properties
            disk_location = PROP.find("./PROPERTY[@name='location']").text
            disk_health = PROP.find("./PROPERTY[@name='health']").text
            disk_health_num = PROP.find("./PROPERTY[@name='health-numeric']").text
            disk_error = PROP.find("./PROPERTY[@name='error']").text
            disk_full_data = {
                "health": disk_health,
                "health-num": disk_health_num,
                "error": disk_error
            }

            # Processing advanced properties
            disk_ext = dict()
            disk_ext['temperature'] = PROP.find("./PROPERTY[@name='temperature-numeric']")
            disk_ext['power-on-hours'] = PROP.find("./PROPERTY[@name='power-on-hours']")
            for prop, value in disk_ext.items():
                if value is not None:
                    disk_full_data[prop] = value.text
            all_components[disk_location] = disk_full_data
    elif component == 'vdisks':
        for PROP in xml.findall("./OBJECT[@name='virtual-disk']"):
            # Processing main vdisk properties
            vdisk_name = PROP.find("./PROPERTY[@name='name']").text
            vdisk_health = PROP.find("./PROPERTY[@name='health']").text
            vdisk_health_num = PROP.find("./PROPERTY[@name='health-numeric']").text
            vdisk_status = PROP.find("./PROPERTY[@name='status']").text
            vdisk_status_num = PROP.find("./PROPERTY[@name='status-numeric']").text
            vdisk_owner = PROP.find("./PROPERTY[@name='owner']").text
            vdisk_owner_pref = PROP.find("./PROPERTY[@name='preferred-owner']").text
            vdisk_full_data = {
                "health": vdisk_health,
                "health-num": vdisk_health_num,
                "status": vdisk_status,
                "status-num": vdisk_status_num,
                "owner": vdisk_owner,
                "owner-pref": vdisk_owner_pref
            }
            all_components[vdisk_name] = vdisk_full_data
    elif component == 'controllers':
        for PROP in xml.findall("./OBJECT[@name='controllers']"):
            # Processing main controller properties
            ctrl_id = PROP.find("./PROPERTY[@name='controller-id']").text
            ctrl_health = PROP.find("./PROPERTY[@name='health']").text
            ctrl_health_num = PROP.find("./PROPERTY[@name='health-numeric']").text
            ctrl_status = PROP.find("./PROPERTY[@name='status']").text
            ctrl_status_num = PROP.find("./PROPERTY[@name='status-numeric']").text
            ctrl_rd_status = PROP.find("./PROPERTY[@name='redundancy-status']").text
            ctrl_rd_status_num = PROP.find("./PROPERTY[@name='redundancy-status-numeric']").text
            # Making full controller dict
            ctrl_full_data = {
                "health": ctrl_health,
                "health-num": ctrl_health_num,
                "status": ctrl_status,
                "status-num": ctrl_status_num,
                "redundancy": ctrl_rd_status,
                "redundancy-num": ctrl_rd_status_num
            }

            # Processing advanced controller properties
            ctrl_ext = dict()
            ctrl_ext['flash-health'] = PROP.find("./OBJECT[@basetype='compact-flash']/PROPERTY[@name='health']")
            ctrl_ext['flash-health-num'] = PROP.find(
                "./OBJECT[@basetype='compact-flash']/PROPERTY[@name='health-numeric']")
            ctrl_ext['flash-status'] = PROP.find("./OBJECT[@basetype='compact-flash']/PROPERTY[@name='status']")
            ctrl_ext['flash-status-num'] = PROP.find(
                "./OBJECT[@basetype='compact-flash']/PROPERTY[@name='status-numeric']")
            for prop, value in ctrl_ext.items():
                if value is not None:
                    ctrl_full_data[prop] = value.text

            # Getting info about all FC ports
            ctrl_ports = {}
            for FC in PROP.findall("./OBJECT[@name='ports']"):
                # Processing main ports properties
                port_name = FC.find("./PROPERTY[@name='port']").text
                port_health = FC.find("./PROPERTY[@name='health']").text
                port_health_num = FC.find("./PROPERTY[@name='health-numeric']").text
                if port_health_num != '4':
                    port_full_data = {
                        "health": port_health,
                        "health-num": port_health_num
                    }

                    # Processing advanced ports properties
                    port_ext = dict()
                    port_ext['port-status'] = FC.find("./PROPERTY[@name='status']")
                    port_ext['port-status-num'] = FC.find("./PROPERTY[@name='status-numeric']")
                    port_ext['sfp-status'] = FC.find("./OBJECT[@name='port-details']/PROPERTY[@name='sfp-status']")
                    for prop, value in port_ext.items():
                        if value is not None:
                            port_full_data[prop] = value.text

                    ctrl_ports[port_name] = port_full_data
                # Adds ports info to the final dict
                ctrl_full_data['ports'] = ctrl_ports
            all_components[ctrl_id] = ctrl_full_data
    elif component == 'enclosures':
        for PROP in xml.findall("./OBJECT[@name='enclosures']"):
            # Processing main enclosure properties
            encl_id = PROP.find("./PROPERTY[@name='enclosure-id']").text
            encl_health = PROP.find("./PROPERTY[@name='health']").text
            encl_health_num = PROP.find("./PROPERTY[@name='health-numeric']").text
            encl_status = PROP.find("./PROPERTY[@name='status']").text
            encl_status_num = PROP.find("./PROPERTY[@name='status-numeric']").text
            # Making full enclosure dict
            encl_full_data = {
                "health": encl_health,
                "health-num": encl_health_num,
                "status": encl_status,
                "status-num": encl_status_num
            }

            # Getting info about all power supplies
            encl_all_ps = {}
            for PS in PROP.findall("./OBJECT[@name='power-supplies']"):
                # Processing main power supplies properties
                ps_id = PS.find("./PROPERTY[@name='durable-id']").text
                ps_health = PS.find("./PROPERTY[@name='health']").text
                ps_health_num = PS.find("./PROPERTY[@name='health-numeric']").text
                ps_status = PS.find("./PROPERTY[@name='status']").text
                ps_status_num = PS.find("./PROPERTY[@name='status-numeric']").text
                ps_dc12v = PS.find("./PROPERTY[@name='dc12v']").text
                ps_dc5v = PS.find("./PROPERTY[@name='dc5v']").text
                ps_dc33v = PS.find("./PROPERTY[@name='dc33v']").text
                ps_dc12i = PS.find("./PROPERTY[@name='dc12i']").text
                ps_dc5i = PS.find("./PROPERTY[@name='dc5i']").text
                ps_full_data = {
                    "health": ps_health,
                    "health-num": ps_health_num,
                    "status": ps_status,
                    "status-num": ps_status_num,
                    "power-12v": ps_dc12v,
                    "power-5v": ps_dc5v,
                    "power-33v": ps_dc33v,
                    "power-12i": ps_dc12i,
                    "power-5i": ps_dc5i
                }
                # Processing advanced power supplies properties
                ps_ext = dict()
                ps_ext['temperature'] = PS.find("./PROPERTY[@name='dctemp']")
                for prop, value in ps_ext.items():
                    if value is not None:
                        ps_full_data[prop] = value.text
                # Fans
                for FAN in PROP.findall(".//OBJECT[@name='fan-details']"):
                    # Processing main fan properties
                    fan_id = FAN.find(".PROPERTY[@name='durable-id']").text
                    fan_health = FAN.find(".PROPERTY[@name='health']").text
                    fan_health_num = FAN.find(".PROPERTY[@name='health-numeric']").text
                    fan_status = FAN.find(".PROPERTY[@name='status']").text
                    fan_status_num = FAN.find(".PROPERTY[@name='status-numeric']").text
                    fan_speed = FAN.find(".PROPERTY[@name='speed']").text
                    fan_full_data = {
                        "health": fan_health,
                        "health-num": fan_health_num,
                        "status": fan_status,
                        "status-num": fan_status_num,
                        "speed": fan_speed
                    }
                    ps_full_data[fan_id] = fan_full_data
                encl_all_ps[ps_id] = ps_full_data
                # Adding power supplies data to the full enclosure dict
                encl_full_data['power-supplies'] = encl_all_ps
            all_components[encl_id] = encl_full_data
    else:
        raise SystemExit('ERROR: You should provide the storage component (vdisks, disks, controllers)')
    return json.dumps(all_components, separators=(',', ':'))


if __name__ == '__main__':
    # Current program version
    VERSION = '0.4.1'

    # Parse all given arguments
    parser = ArgumentParser(description='Zabbix script for HP MSA XML API.', add_help=True)
    parser.add_argument('-d', '--discovery', action='store_true', help='Making discovery')
    parser.add_argument('-g', '--get', '--health', type=str, help='ID of MSA part which status we want to get',
                        metavar='[DISKID|VDISKNAME|CONTROLLERID|ENCLOSUREID|all]')
    parser.add_argument('-u', '--user', default='monitor', type=str, help='User name to login in MSA')
    parser.add_argument('-p', '--password', default='!monitor', type=str, help='Password for your user')
    parser.add_argument('-f', '--loginfile', type=str, help='Path to file contains login and password')
    parser.add_argument('-m', '--msa', type=str, help='DNS name or IP address of MSA', metavar='[IP|DNSNAME]')
    parser.add_argument('-c', '--component', type=str, choices=['disks', 'vdisks', 'controllers', 'enclosures'],
                        help='MSA component name.', metavar='[disks|vdisks|controllers|enclosures]')
    parser.add_argument('-v', '--version', action='version', version=VERSION, help='Print the script version and exit')
    parser.add_argument('-s', '--savexml', type=str, help='Save response from storage as XML')
    parser.add_argument('--showcache', action='store_true', help='Display cache data')
    parser.add_argument('--https', type=str, choices=['direct', 'verify'], help='Use https instead http',
                        metavar='[direct|verify]')
    args = parser.parse_args()

    # Create cache table if it not exists
    CACHE_DB = prepare_tmp() + 'zbx-hpmsa.cache.db'
    if not os.path.exists(CACHE_DB):
        sql_op('CREATE TABLE IF NOT EXISTS skey_cache ('
               'dns_name TEXT NOT NULL, '
               'ip TEXT NOT NULL, '
               'proto TEXT NOT NULL, '
               'expired TEXT NOT NULL, '
               'skey TEXT NOT NULL DEFAULT 0, '
               'PRIMARY KEY (dns_name, ip, proto))')

    # Display cache data and exit
    if args.showcache:
        print("{:^30} {:^15} {:^7} {:^19} {:^32}".format('hostname', 'ip', 'proto', 'expired', 'sessionkey'))
        print("{:-^30} {:-^15} {:-^7} {:-^19} {:-^32}".format('-', '-', '-', '-', '-'))
        for cache in sql_op('SELECT * FROM skey_cache', fetch_all=True):
            name, ip, proto, expired, skey = cache
            print("{:30} {:15} {:^7} {:19} {:32}".format(
                name, ip, proto, datetime.fromtimestamp(float(expired)).strftime("%H:%M:%S %d.%m.%Y"), skey))
        exit(0)

    # Set msa_connect - IP or DNS name and determine to use https or not
    USE_HTTPS = args.https in ['direct', 'verify']
    VERIFY_SSL = args.https == 'verify'
    MSA_CONNECT = args.msa if VERIFY_SSL else gethostbyname(args.msa)

    # Make no possible to use '--discovery' and '--get' options together
    if args.discovery and args.get:
        raise SystemExit("Syntax error: Cannot use '-d|--discovery' and '-g|--get' options together.")

    # Make login hash string
    if args.loginfile:
        CRED_HASH = make_pwd_hash(args.loginfile, isfile=True)
    else:
        CRED_HASH = make_pwd_hash('_'.join([args.user, args.password]))

    # Getting sessionkey
    skey = get_skey(MSA_CONNECT, CRED_HASH)

    # Make discovery
    if args.discovery:
        print(make_discovery(MSA_CONNECT, args.component, skey))
    # Getting health
    elif args.get and args.get != 'all':
        print(get_health(MSA_CONNECT, args.component, args.get, skey))
    # Making bulk request for all possible component statuses
    elif args.get == 'all':
        print(get_full_data(MSA_CONNECT, args.component, skey))
    else:
        raise SystemExit("Syntax error: You must use '--discovery' or '--get' option anyway.")
