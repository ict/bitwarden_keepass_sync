import argparse
import csv
import json
import os.path
import xml.etree.ElementTree as ET


def read_bw(bw_file):
    entries = {}
    with open(bw_file, 'rb') as bw_in:
        bw_data = json.load(bw_in)
        for item in bw_data["items"]:
            if item["type"] != 1:
                continue  # skip non-login entries
            entries[item["name"]] = item["login"]
    return entries

GENERIC_CSV_FIELDS = [
    "folder",
    "favorite",
    "type",
    "name",
    "notes",
    "fields",
    "login_uri",
    "login_username",
    "login_password",
    "login_totp",
]


def create_generic_csv_dict(name, entry):
    """ https://help.bitwarden.com/article/import-data/ """
    try:
        url = entry["url"]
    except KeyError:
        try:
            url = entry['uris'][0]['uri']
        except (KeyError, IndexError):
            url = ""
    return {
        "folder": "",
        "favorite": "",
        "type": 1,
        "name": name,
        "notes": "",
        "fields": "",
        "login_uri": url,
        "login_username": entry["username"],
        "login_password": entry["password"],
        "login_totp": "",
    }


def compare_to_kp(kp_db, bw_entries):
    changed = False
    bw_set = {x for x in bw_entries}
    kp_set = set()
    to_bitwarden = {}
    for node in kp_db.findall('.//Group/Entry'):
        name = node.find("./String[Key='Title']/Value").text
        user = node.find("./String[Key='UserName']/Value").text
        password = node.find("./String[Key='Password']/Value").text
        url = node.find("./String[Key='URL']/Value").text
        kp_set.add(name)
        if name in bw_entries:
            new_user = bw_entries[name]["username"]
            new_password = bw_entries[name]["password"]
            if new_user != user:
                print("{}: Username changed from '{}' to '{}'".format(name, user, new_user))
                node.find("./String[Key='UserName']/Value").text = new_user
                changed = True
            if new_password != password:
                print("{}: Pass changed from '{}...' to '{}...'".format(name, password[0], new_password[0]))
                node.find("./String[Key='Password']/Value").text = new_password
                changed = True
        else:
            to_bitwarden[name] = {
                "username": user,
                "password": password,
                "url": url
            }

    to_keepass = bw_set - kp_set
    return changed, to_bitwarden, to_keepass


def main(args):
    print("Processing...")
    bw_entries = read_bw(args.bitwarden_file)
    kp_db = ET.parse(args.keepass_file)
    changed, to_bitwarden, to_keepass = compare_to_kp(kp_db, bw_entries)
    print("===")
    print("Entries in KP, but not in BW:", list(to_bitwarden.keys()))
    print("Entries in BW, but not in KP:", to_keepass)

    if args.difference:
        to_keepass_csv = []
        for entry_name in to_keepass:
            csv_entry = create_generic_csv_dict(entry_name, bw_entries[entry_name])
            to_keepass_csv.append(csv_entry)
        if to_keepass_csv:
            to_keepass_filename = 'to-keepass.csv'
            with open(to_keepass_filename, 'w', newline='') as out_file:
                out_csv = csv.DictWriter(out_file, delimiter=',', fieldnames=GENERIC_CSV_FIELDS)
                out_csv.writeheader()
                out_csv.writerows(to_keepass_csv)
            print("Wrote", to_keepass_filename)

        to_bitwarden_csv = []
        for entry_name in to_bitwarden:
            csv_entry = create_generic_csv_dict(entry_name, to_bitwarden[entry_name])
            to_bitwarden_csv.append(csv_entry)
        if to_bitwarden_csv:
            to_bitwarden_filename = 'to-bitwarden.csv'
            with open(to_bitwarden_filename, 'w', newline='') as out_file:
                out_csv = csv.DictWriter(out_file, delimiter=',', fieldnames=GENERIC_CSV_FIELDS)
                out_csv.writeheader()
                out_csv.writerows(to_bitwarden_csv)
            print("Wrote", to_bitwarden_filename)

    if changed:
        out_filename = args.out_xml
        if not out_filename:
            out_filename = "{}-out{}".format(*os.path.splitext(args.keepass_file))
        kp_db.write(out_filename)
        print("===")
        print("Wrote", out_filename)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Import changes from Bitwarden into KeePass"
    )
    parser.add_argument(
        "-b",
        "--bitwarden",
        required=True,
        metavar="JSON_FILE",
        dest="bitwarden_file",
        help="Bitwarden JSON export file"
    )
    parser.add_argument(
        "-k",
        "--keepass",
        required=True,
        metavar="XML_FILE",
        dest="keepass_file",
        help="KeePass 2 XML export file"
    )
    parser.add_argument(
        "-o",
        "--out-xml",
        default=None,
        dest="out_xml",
        help="Ouput KeePass 2 XML file"
    )
    parser.add_argument(
        "-d",
        "--difference",
        dest="difference",
        action="store_true",
        help="Also write CSV importable files for differing entries"
    )
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    main(args)
