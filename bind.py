#!/usr/bin/env python

import configparser
import dns.tsigkeyring
import dns.resolver
import dns.update
import dns.query
import dns.zone

from dns.rdatatype import *

from flask import Flask, jsonify, request

app = Flask(__name__)


def parse_config(config):
    options = {}

    parser = configparser.ConfigParser()
    parser.read(config)

    options['nameserver'] = parser.get('nameserver', 'server')
    options['username'] = parser.get('auth', 'username')
    options['password'] = parser.get('auth', 'password')

    return options


@app.route('/dns/zone/<string:zone_name>', methods=['GET'])
def get_zone(zone_name):

    config = parse_config('config.ini')

    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']

    records = {}

    if not zone_name.endswith('.'):
        zone_name = zone_name + "."

    try:
        zone = dns.zone.from_xfr(dns.query.xfr(config['nameserver'], zone_name))
    except dns.exception.FormError:
        return jsonify({'error': zone_name})

    for (name, ttl, rdata) in zone.iterate_rdatas():
        if rdata.rdtype != SOA:
            if records.get(str(name), 0):
                records[str(name)] = records[str(name)] + [
                    {'Answer': str(rdata), 'RecordType': rdata.rdtype, 'TTL': ttl}]
            else:
                records[str(name)] = [{'Answer': str(rdata), 'RecordType': rdata.rdtype, 'TTL': ttl}]

    return jsonify({zone_name: records})


if __name__ == '__main__':
    app.run(debug=True)