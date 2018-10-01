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

records_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']


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


@app.route('/dns/record/<string:domain>', methods=['GET'])
def get_record(domain):
    config = parse_config('config.ini')

    record = {}

    for records_type in records_types:
        try:
            answers = dns.resolver.query(domain, records_type)
        except dns.resolver.NoAnswer:
            continue

        record.update({records_type: [str(i) for i in answers.rrset]})

    return jsonify({domain: record})


@app.route('/dns/record/<string:domain>/<int:ttl>/<string:record_type>/<string:response>', methods=['GET', 'PUT', 'POST', 'DELETE'])
def manage(domain, ttl, record_type, response):

    zone = b'.'.join(dns.name.from_text(domain).labels[1:])
    config = parse_config('config.ini')

    if record_type not in records_types:
        return jsonify({'error': 'not a valid record type'})

    if request.method == 'PUT' or request.method == 'DELETE':
        resolver = dns.resolver.Resolver()

        resolver.nameservers = [config['nameserver']]
        try:
            answer = resolver.query(domain, record_type)
        except dns.resolver.NXDOMAIN:
            return jsonify({'error': 'domain does not exists'})

    tsig = dns.tsigkeyring.from_text({config['username']: config['password']})
    action = dns.update.Update(zone, keyring=tsig)
    if request.method == 'DELETE':
        action.delete(dns.name.from_text(domain).labels[0])
    elif request.method == 'PUT' or request.method == 'POST':
        action.replace(dns.name.from_text(domain).labels[0], ttl, str(record_type), str(response))

    try:
        response = dns.query.tcp(action, config['nameserver'])
    #print(response)
    except Exception as e:
        print(e)
        return jsonify({'error': 'DNS transaction failed'})

    if response.rcode() == 0:
        return jsonify({domain: 'DNS request successful'})
    else:
        return jsonify({domain: 'DNS request failed'})


if __name__ == '__main__':
    app.run(debug=True, host='192.168.1.127')
