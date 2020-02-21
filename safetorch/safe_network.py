# Copyright (c) Facebook, Inc. and its affiliates.
# All rights reserved.
#
# This source code is licensed under the license found in the
# LICENSE file in the root directory of this source tree.
#

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.nn.parameter import Parameter


class SAFE(nn.Module):
    def __init__(self, config):
        super(SAFE, self).__init__()

        self.conf = config

        self.instructions_embeddings = torch.nn.Embedding(
            self.conf.num_embeddings, self.conf.embedding_size
        )

        self.bidirectional_rnn = torch.nn.GRU(
            input_size=self.conf.embedding_size,
            hidden_size=self.conf.rnn_state_size,
            num_layers=self.conf.rnn_depth,
            bias=True,
            batch_first=True,
            dropout=0,
            bidirectional=True,
        )

        self.WS1 = Parameter(
            torch.Tensor(self.conf.attention_depth, 2 * self.conf.rnn_state_size)
        )
        self.WS2 = Parameter(
            torch.Tensor(self.conf.attention_hops, self.conf.attention_depth)
        )

        self.dense_1 = torch.nn.Linear(
            2 * self.conf.attention_hops * self.conf.rnn_state_size,
            self.conf.dense_layer_size,
            bias=True,
        )
        self.dense_2 = torch.nn.Linear(
            self.conf.dense_layer_size, self.conf.embedding_size, bias=True
        )

    def forward(self, instructions, lengths):

        # for now assume a batch size of 1
        batch_size = 1

        # check valid input
        if lengths[0] <= 0:
            return torch.zeros(batch_size, self.conf.embedding_size)

        # each functions is a list of embeddings id
        # (an id is an index in the embedding matrix)
        # with this we transform it in a list of embeddings vectors.
        instructions_vectors = self.instructions_embeddings(instructions)

        # consider only valid instructions (defdined by lengths)
        valid_instructions = torch.split(instructions_vectors, lengths[0], 0)[0]

        # We create the GRU RNN
        output, h_n = self.bidirectional_rnn(valid_instructions.unsqueeze(0))

        pad = torch.zeros(
            1, self.conf.max_instructions - lengths[0], self.conf.embedding_size
        )

        # We create the matrix H
        H = torch.cat((output, pad), 1)

        # We do a tile to account for training batches
        ws1_tiled = self.WS1.unsqueeze(0)
        ws2_tiled = self.WS2.unsqueeze(0)

        # we compute the matrix A
        A = torch.softmax(
            ws2_tiled.matmul(torch.tanh(ws1_tiled.matmul(H.transpose(1, 2)))), 2
        )

        # embedding matrix M
        M = A.matmul(H)

        # we create the flattened version of M
        flattened_M = M.view(
            batch_size, 2 * self.conf.attention_hops * self.conf.rnn_state_size
        )

        dense_1_out = F.relu(self.dense_1(flattened_M))
        function_embedding = F.normalize(self.dense_2(dense_1_out), dim=1, p=2)

        return function_embedding
