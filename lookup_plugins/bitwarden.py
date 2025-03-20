#!/usr/bin/env python

# (c) 2018, Matt Stofko <matt@mjslabs.com>
# GNU General Public License v3.0+ (see LICENSE or
# https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This plugin can be run directly by specifying the field followed by a list of
# entries, e.g.  bitwarden.py password google.com wufoo.com
#
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
import sys

from subprocess import Popen, PIPE, STDOUT, check_output

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()


DOCUMENTATION = """
lookup: bitwarden
author:
  - Matt Stofko <matt@mjslabs.com>
requirements:
  - bw (command line utility)
  - BW_SESSION environment var (from `bw login` or `bw unlock`)
short_description: look up data from a bitwarden vault
description:
  - use the bw command line utility to grab one or more items stored in a
    bitwarden vault
options:
  _terms:
    description: name of item that contains the field to fetch
    required: true
field:
  description: field to return from bitwarden
  default: 'password'
custom_field:
  description: If True, look up named field in custom fields instead
      of top-level dictionary.
sync:
  description: If True, call `bw sync` before lookup
"""

EXAMPLES = """
- name: get 'username' from Bitwarden entry 'Google'
  debug:
    msg: "{{ lookup('bitwarden', 'Google', field='username') }}"
"""

RETURN = """
  _raw:
    description:
      - Items from Bitwarden vault
"""


class Bitwarden(object):
    def __init__(self, path, session=None):
        self._cli_path = path
        self._bw_session = session or os.environ.get("BW_SESSION", "")
        try:
            check_output([self._cli_path, "--version"])
        except OSError:
            raise AnsibleError("Command not found: {0}".format(self._cli_path))

    @property
    def session(self):
        return self._bw_session

    @session.setter
    def session(self, value):
        self._bw_session = value

    @property
    def cli_path(self):
        return self._cli_path

    @property
    def logged_in(self):
        # Parse Bitwarden status to check if logged in
        return self.status() == 'unlocked'

    def _run(self, args):
        my_env = os.environ.copy()
        if self.session:
            my_env["BW_SESSION"] = self.session
        else:
            raise AnsibleError("BW_SESSION is not set. Please set BW_SESSION and try again.")

        # Verwende self._cli_path statt self.cli_path
        p = Popen([self._cli_path] + args, stdin=PIPE, stdout=PIPE, stderr=STDOUT, env=my_env)
        out, _ = p.communicate()
        out = out.decode()
        rc = p.wait()

        if rc != 0:
            if "Vault is locked." in out:
                raise AnsibleError("Error: Bitwarden vault is locked. Run 'bw unlock' and set BW_SESSION.")
            elif "You are not logged in." in out:
                raise AnsibleError("Error: Not logged in to Bitwarden. Run 'bw login'.")
            else:
                raise AnsibleError(f"Bitwarden CLI error: {out.strip()}")
        return out.strip()

    def sync(self):
        self._run(['sync'])

    def status(self):
        try:
            data = json.loads(self._run(['status']))
            return data['status']
        except json.JSONDecodeError as e:
            raise AnsibleError(f"Error decoding Bitwarden status: {e}")

    def get_entry(self, key, field):
        return self._run(["get", field, key])

    def get_notes(self, key):
        data = json.loads(self.get_entry(key, 'item'))
        return data['notes']
    def get_custom_field(self, key, field):
        data = json.loads(self.get_entry(key, 'item'))
        for f in data.get('fields', []):
            if f['name'] == field:
                return f['value']
        raise AnsibleError(f"Custom field '{field}' not found in item '{key}'.")

    def get_attachments(self, key, itemid, output):
        attachment = ['get', 'attachment', '{}'.format(
            key), '--output={}'.format(output), '--itemid={}'.format(itemid)]
        return self._run(attachment)


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        session = kwargs.get('session')
        bw = Bitwarden(path=kwargs.get('path', 'bw'), session=session)

        if not bw.logged_in:
            raise AnsibleError("Not logged into Bitwarden. Please run 'bw login' or 'bw unlock' and set BW_SESSION.")


        field = kwargs.get('field', 'password')
        values = []

        if kwargs.get('sync'):
            bw.sync()

        for term in terms:
            if kwargs.get('custom_field'):
                values.append(bw.get_custom_field(term, field))
            elif field == 'notes':
                values.append(bw.get_notes(term))
            elif kwargs.get('attachments'):
                if kwargs.get('itemid'):
                    itemid = kwargs.get('itemid')
                    output = kwargs.get('output', term)
                    values.append(bw.get_attachments(term, itemid, output))
                else:
                    raise AnsibleError("Missing value for - itemid - "
                                       "Please set parameters as example: - "
                                       "itemid='f12345-d343-4bd0-abbf-4532222' ")
            else:
                values.append(bw.get_entry(term, field))
        return values


def main():
    if len(sys.argv) < 3:
        print("Usage: {0} <field> <name> [name name ...]"
              .format(os.path.basename(__file__)))
        return -1

    print(LookupModule().run(sys.argv[2:], None, field=sys.argv[1]))

    return 0


if __name__ == "__main__":
    sys.exit(main())
