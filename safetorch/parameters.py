# Copyright (c) Facebook, Inc. and its affiliates.
# All rights reserved.
#
# This source code is licensed under the license found in the
# LICENSE file in the root directory of this source tree.
#


class Config:
    def __init__(self):
        self.num_embeddings = 527683
        self.embedding_size = 100  # dimension of the function embedding

        ## RNN PARAMETERS, these parameters are only used for RNN model.
        self.rnn_state_size = 50  # dimesion of the rnn state
        self.rnn_depth = 1  # depth of the rnn
        self.max_instructions = 150  # number of instructions

        ## ATTENTION PARAMETERS
        self.attention_hops = 10
        self.attention_depth = 250

        # RNN SINGLE PARAMETER
        self.dense_layer_size = 2000
