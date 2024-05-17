"""

 YaraBin (Yara + Binary)

 This generates Yara rules from function prologs, for matching and hunting

 Questions of comments? Hit me up @chrisdoman

"""

import binascii
import re
import os
import argparse
import math
import sqlite3
import hashlib

# What percent overlap required for two malware samples considered to be the same family?
# From 0 (0%) to 1 (100%). A large number means a tighter yara signature
# will be created
percent_tight_match = 0.8

seen_patterns = {}
conn = sqlite3.connect('db.db')
db = conn.cursor()
db.execute('PRAGMA synchronous=OFF')


def parse_args():
    parser = argparse.ArgumentParser(
        description='Yabin - Signatures and searches malware')
    parser.add_argument('-y', '--yara', help='Generate yara rule for the file or folder', required=False)
    parser.add_argument('-yh', '--yaraHunt',
                        help='Generate wide yara rule (any of, not all of).\r\n Useful for hunting for related samples or potentially malicious files that share any of the code - but liable to false positive',
                        required=False)
    parser.add_argument('-d', '--deleteDatabase', help='Empty the whitelist and malware database', action='store_true')
    parser.add_argument('-w', '--addToWhitelist', help='Add a file or folder to the whitelist', required=False)
    parser.add_argument('-f', '--fuzzyHash', help='Generate a fuzzy hash for the file', required=False)
    parser.add_argument('-m', '--malwareAdd', help='Add malware file or folder to malware database to be searched',
                        required=False)
    parser.add_argument('-s', '--malwareSearch', help='Search for samples related to this file', required=False)

    args = vars(parser.parse_args())

    if args['yara']:
        yara(args['yara'])
    if args['yaraHunt']:
        yara(args['yaraHunt'], False)
    if args['deleteDatabase']:
        delete_database()
    if args['addToWhitelist']:
        add_to_whitelist(args['addToWhitelist'])
    if args['fuzzyHash']:
        fuzzy_hash(args['fuzzyHash'])
    if args['malwareAdd']:
        add_malware(args['malwareAdd'])
    if args['malwareSearch']:
        malware_search(args['malwareSearch'])


def get_byte_patterns(filename, ignore_whitelist=False):
    with open(filename, 'rb') as f:
        content = f.read()
    hex_value = binascii.hexlify(content).decode('utf-8')
    # Add - every two characters so we match -xx- not x-x
    hex_value = 'x'.join([hex_value[i:i + 2] for i in range(0, len(hex_value), 2)])
    seen = {}
    for match in re.findall(prolog_regex, hex_value):
        bit = match[0].replace('x', '')
        if bit not in seen:
            if ignore_whitelist or not whitelisted(bit):
                # Only include high entropy patterns, ie) avoid 0000000 or
                # 1111111 etc.
                # if entropy(bit) > 0:
                seen[bit] = entropy(bit)

    return seen


def load_prolog():
    prolog_regex = '('
    with open('regex.txt') as file:
        for l in file.readlines():
            line = l.strip()
            if not line.startswith('#'):
                if len(line) > 3:
                    prolog_regex += line + '|'
    prolog_regex += ')'
    prolog_regex = prolog_regex.replace('|)', ')')
    return prolog_regex


# Get the shannon entropy of a string


def entropy(string):
    prob = [float(string.count(c)) / len(string)
            for c in dict.fromkeys(list(string))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy


def gen_fuzzy_hash(filename):
    # Print out those that aren't in the whitelist
    byte_patterns = get_byte_patterns(filename)
    patterns = []
    for s in byte_patterns:
        patterns.append(s)

    patterns.sort()
    # Just print the first sorted pattern... a vey poor mans fuzzy hash
    for s in patterns:
        print(filename + ',' + s)
        return


# def gen_yara(filename, single_file, tight=True, max_lines=3000, min_patterns=
def gen_yara(filename, tight=True, max_lines=3000, min_patterns=0):
    global seen_patterns
    global percent_tight_match

    # Print out those that aren't in the whitelist
    byte_patterns = get_byte_patterns(filename)

    if tight:
        # Dont print the same rule twice
        if str(byte_patterns) not in seen_patterns:
            seen_patterns[str(byte_patterns)] = 1
            # If we have no, or only one pattern, it probably won't be a tight
            # enough signature
            if len(byte_patterns) > min_patterns:
                print('rule tight_' + filename.replace('/', '_').replace('.', '') + ' {')
                print(' strings:')

                count = 1
                for s in byte_patterns:
                    if count < max_lines:
                        count = count + 1
                        print('  $a_' + str(count) + ' = { ' + s + ' }')

                print(' condition:')
                tight_decimal = int(round(count * percent_tight_match))
                print('  ' + str(tight_decimal) + ' of them')
                print('}')
                print('\r\n\r\n')

    # if not tight:
    #     # Dont print the same rule twice
    #     for s in byte_patterns.iteritems():

    #         if s in seen_patterns or singleFile:
    #             if s not in seen_patterns:
    #                 seen_patterns[s] = 1
    #             seen_patterns[s] = seen_patterns[s] + 1
    #             if seen_patterns[s] == 2:

    #                 fname = filename.replace('/', '_').replace('.', '')
    #                 print 'rule ' + fname + '_hunt_' + s[0] + ' {'
    #                 print ' // File: ' + fname
    #                 print ' strings:'
    #                 print '  $a_1 = { ' + s[0] + ' }'
    #                 print ' condition:'
    #                 print '     all of them'
    #                 print '}'
    #                 print '\r\n\r\n'
    #         else:
    #             if s not in seen_patterns:
    #                 seen_patterns[s] = 1

    if not tight:
        # Dont print the same rule twice
        if str(byte_patterns) not in seen_patterns:
            seen_patterns[str(byte_patterns)] = 1
            # If we have no, or only one pattern, it probably won't be a tight
            # enough signature
            if len(byte_patterns) > min_patterns:
                print('rule tight_' + filename.replace('/', '_').replace('.', '') + ' {')
                print(' strings:')

                count = 1
                for s in byte_patterns:
                    if count < max_lines:
                        count = count + 1
                        print('  $a_' + str(count) + ' = { ' + s + ' }')

                print(' condition:')
                tight_decimal = int(round(count * percent_tight_match))
                print('  any of them')
                print('}')
                print('\r\n\r\n')


def fuzzy_hash(filename, tight=True):
    if os.path.isdir(filename):
        for f in os.listdir(filename):
            gen_fuzzy_hash(filename + '/' + f)
    else:
        if os.path.isfile(filename):
            gen_fuzzy_hash(filename)


def yara(filename, tight=True):
    if os.path.isdir(filename):
        for f in os.listdir(filename):
            gen_yara(filename + '/' + f, False, tight)
    else:
        if os.path.isfile(filename):
            gen_yara(filename, True, tight)


# Returns true if a pattern is whitelisted


def whitelisted(pattern):
    db.execute('SELECT * FROM whitelist WHERE pattern ="' + pattern + '"')
    result = db.fetchone()
    if not result:
        return False
    return True


def add_to_whitelist(folder):
    # Minimum number of samples a pattern must be in
    min_seen = 1
    count = 0

    # If we dont care how often it's been seen, just insert it
    if min_seen == 0:
        for f in os.listdir(folder):
            count = count + 1
            print('Processed ' + str(count) + ' file(s)')
            print('Processing ' + f)
            new_seen = get_byte_patterns(folder + '/' + f, True)
            for pattern in new_seen:
                db.execute(
                    'insert or ignore into whitelist (pattern) values ("' + pattern + '")')
            conn.commit()

    # Otherwise actually keep track of how many samples a pattern has been in
    else:
        seen = {}
        # Built a count of how often every pattern was seen
        for f in os.listdir(folder):
            count = count + 1
            print('Processed ' + str(count) + ' file(s)')
            new_seen = get_byte_patterns(folder + '/' + f, True)
            for pattern in new_seen:
                if pattern not in seen:
                    seen[pattern] = 1
                else:
                    seen[pattern] = seen[pattern] + 1

        total = 0
        # Insert every pattern seen > x times into the whitelist
        for pattern, count in seen.iteritems():
            if count > min_seen:
                total = total + 1
                db.execute(
                    'insert or ignore into whitelist (pattern) values ("' + pattern + '")')

    conn.commit()


def gen_sample(filename):
    md5 = hashlib.md5(open(filename, 'rb').read()).hexdigest()
    # Print out those that aren't in the whitelist
    byte_patterns = get_byte_patterns(filename)
    for pattern in byte_patterns:
        db.execute('insert or ignore into malware (pattern, md5) values ("' +
                   pattern + '", "' + md5 + '")')


def delete_database():
    db.execute('DROP TABLE IF EXISTS whitelist')
    db.execute('DROP TABLE IF EXISTS malware')
    db.execute('CREATE TABLE whitelist (pattern text)')
    db.execute('CREATE UNIQUE INDEX whitelist_index on whitelist (pattern)')
    db.execute('CREATE TABLE malware (pattern text, md5 text)')
    db.execute('CREATE UNIQUE INDEX malware_index on malware (pattern, md5)')


# Add a file or folder to malware db
def add_malware(filename):
    print('Adding samples to malware database')
    if os.path.isdir(filename):
        for f in os.listdir(filename):
            gen_sample(filename + '/' + f)
    else:
        if os.path.isfile(filename):
            gen_sample(filename)
    conn.commit()
    print('Added samples')


# For every pattern in file, find related
def malware_search(filename):
    md5 = hashlib.md5(open(filename, 'rb').read()).hexdigest()
    pattern_lookups = {}
    found_samples = set()

    # Print out those that aren't in the whitelist
    byte_patterns = get_byte_patterns(filename)
    for pattern in byte_patterns:
        related_samples = find_related(pattern)

        for sample in related_samples:
            if sample not in found_samples and sample != md5:
                found_samples.add(sample)
                pattern_lookups[sample] = pattern

    if len(found_samples) > 0:
        print('Found related samples:')
        for sample in found_samples:
            print(sample + ' matched via ' + pattern_lookups[sample])
    else:
        print('No related samples found')


def find_related(pattern):
    db.execute('SELECT md5 FROM malware WHERE pattern ="' + pattern + '"')
    rows = db.fetchall()
    to_return = []
    for row in rows:
        to_return.append(row[0])

    return to_return


# This regex decides what patterns we will extract
prolog_regex = load_prolog()

parse_args()
