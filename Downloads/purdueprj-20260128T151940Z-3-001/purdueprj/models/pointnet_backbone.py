import torch
import torch.nn as nn
from models.snn_layers import LIFLayer

class PointNetBackbone(nn.Module):
    def __init__(self, hidden_dims=[64,128,256]):
        super().__init__()
        self.layers = nn.ModuleList()
        in_dim = 3
        for h in hidden_dims:
            self.layers.append(LIFLayer(in_dim, h))
            in_dim = h

    def reset_state(self, batch_size, device=None):
        for layer in self.layers:
            layer.reset_state(batch_size, device)

    def forward(self, pts):
        # pts: [B, N, 3]
        B, N, _ = pts.shape
        x = pts.view(B*N, -1)  # merge points
        for layer in self.layers:
            spk, mem = layer(x)
            x = mem
        return mem.view(B, N, -1)  # unmerge
