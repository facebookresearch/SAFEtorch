# Copyright (c) Facebook, Inc. and its affiliates.
# All rights reserved.
#
# This source code is licensed under the license found in the
# LICENSE file in the root directory of this source tree.
#

import r2pipe
import json
import sys


class BinaryAnalyzer():
    def __init__(self, path):
        self.r2 = r2pipe.open(path, flags=["-2"])
        self.r2.cmd("aaa")
        self.arch = None
        self.bits = None
        try:
            info = json.loads(self.r2.cmd("ij"))["bin"]
            self.arch = info["arch"]
            self.bits = info["bits"]
        except:
            print(f"Error loading file: {path}", file=sys.stderr)
        try:
            self.afl = self.r2.cmdj("aflj")
        except:
            self.afl = []

    def get_hexasm(self, address):
        data = filter(None, self.r2.cmd(f"pxf @ {address}").split("\n")[1:])
        hexasm = ""
        for i in data:
            hexasm += "".join(i.split("  ")[1].split())
        return hexasm

    def get_functions(self):
        offsets = set()
        for f in self.afl:
            offsets.add(f.get("offset", None))
            for call in f.get("callrefs", []):
                if call.get("type", None) == "CALL":
                    offsets.add(call.get("addr", None))
        return list(filter(None, offsets))
