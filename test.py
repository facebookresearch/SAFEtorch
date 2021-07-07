# Copyright (c) Facebook, Inc. and its affiliates.
# All rights reserved.
#
# This source code is licensed under the license found in the
# LICENSE file in the root directory of this source tree.
#

from utils.function_normalizer import FunctionNormalizer
from utils.instructions_converter import InstructionsConverter
from utils.capstone_disassembler import disassemble
from utils.radare_analyzer import BinaryAnalyzer
from safetorch.safe_network import SAFE
from safetorch.parameters import Config
import torch

import sys

binary_path = sys.argv[1]

# initialize SAFE
config = Config()
safe = SAFE(config)

# load instruction converter and normalizer
I2V_FILENAME = "model/word2id.json"
converter = InstructionsConverter(I2V_FILENAME)
normalizer = FunctionNormalizer(max_instruction=150)

# load SAFE weights
SAFE_torch_model_path = "model/SAFEtorch.pt"
state_dict = torch.load(SAFE_torch_model_path)
safe.load_state_dict(state_dict)
safe = safe.eval()

# analyze the binary
binary = BinaryAnalyzer(binary_path)
offsets = binary.get_functions()

# generate each function embedding
for offset in offsets:
    asm = binary.get_hexasm(offset)
    instructions = disassemble(asm, binary.arch, binary.bits)
    converted_instructions = converter.convert_to_ids(instructions)
    instructions, length = normalizer.normalize_functions(
        [converted_instructions])
    tensor = torch.LongTensor(instructions[0])
    function_embedding = safe(tensor, length)
    print(hex(offset), function_embedding)
