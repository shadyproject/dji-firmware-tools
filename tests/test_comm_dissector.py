# -*- coding: utf-8 -*-

""" Test for dji-firmware-tools, comm_dissector scripts.

    This test verifies functions of the script by using
    `tshark`, command line Wireshark utility.
"""

# Copyright (C) 2023 Mefistotelis <mefistotelis@gmail.com>
# Copyright (C) 2023 Original Gangsters <https://dji-rev.slack.com/>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import subprocess
import os
import re
import sys
import struct
import time
import datetime
import pytest

LOGGER = logging.getLogger(__name__)

pckt_mavic_air_fcc = [0x55, 0x17, 0x04, 0x38, 0x02, 0x0e, 0x1d, 0x00, 0x40, 0x07, 0x30, 0x55, 0x53, 0x00, 0x00, 0x55, 0x53, 0x00, 0x00, 0x01, 0x00, 0xfe, 0x5d]
pckt_mini_2_fcc = [0x55, 0x18, 0x04, 0x20, 0x02, 0x09, 0x00, 0x00, 0x40, 0x09, 0x27, 0x00, 0x02, 0x48, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x81, 0x1f]

def write_one_packet_pcap(fname, userdlt, data):
    with open(fname, "wb") as out:
        out.write(struct.pack("=IHHiIII",
            0xa1b2c3d4,   # magic number
            2,            # major version number
            4,            # minor version number
            0,            # GMT to local correction
            0,            # accuracy of timestamps
            65535,        # max length of captured packets, in octets
            147+userdlt, # data link type (DLT) - USER_0
        ))

        dtime = datetime.datetime.now()
        timestamp = int(time.mktime(dtime.timetuple()))
        out.write(struct.pack("=IIII",
            timestamp,        # timestamp seconds
            dtime.microsecond, # timestamp microseconds
            len(data),        # number of octets of packet saved in file
            len(data),        # actual length of packet
        ))
        out.write(data)

def run_comm_dissector_tshark_show(cmd, inp_file, proto_name, pkt_cmd, env=None):
    command = [cmd, '-r', inp_file, '-V']
    LOGGER.info(' '.join(command))
    prc_result = subprocess.run(command, env=env, capture_output=True)
    assert prc_result.returncode == 0
    # Check if protocol name is found in tshark output (protocol was recognized)
    assert str(prc_result.stdout).find(proto_name) > 0
    # Check if command from the packet is found in tshark output (packet header was dissected)
    match = re.search(r'\s+Cmd: [A-Za-z0-9 \//,.-]+ [\(]0x([0-9a-f]+)[\)]', str(prc_result.stdout), re.IGNORECASE)
    assert match
    assert int(match.group(1), 16) == pkt_cmd

def case_comm_dissector_tshark_show(pcap_file, userdlt, proto_name, pckt, env=None):
    pkt_cmd = int(pckt[10])
    write_one_packet_pcap(pcap_file, userdlt, bytearray(pckt))
    run_comm_dissector_tshark_show("tshark", str(pcap_file), proto_name, pkt_cmd, env=env)

@pytest.mark.comm
def test_comm_dissector_tshark_show(tmp_path):
    """ Test dissecting a packet with Wiresharks tshark.
    """
    test_env = os.environ.copy()
    case_comm_dissector_tshark_show(tmp_path / "dji-packet-mavair.pcap", 3, "DJI_DUMLv1", pckt_mavic_air_fcc, env=test_env)
    case_comm_dissector_tshark_show(tmp_path / "dji-packet-mini2.pcap",  3, "DJI_DUMLv1", pckt_mini_2_fcc, env=test_env)
