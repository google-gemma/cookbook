import torch
import torch.nn as nn
from models.snn_layers import LIFLayer

class TemporalSNN(nn.Module):
    def __init__(self, dim=256):
        super().__init__()
        self.lif1 = LIFLayer(dim, dim)
        self.lif2 = LIFLayer(dim, dim)
        self.fc = nn.Linear(dim, 10)  # 10 classes for ModelNet10

    def reset_state(self, batch_size, device=None):
        self.lif1.reset_state(batch_size, device)
        self.lif2.reset_state(batch_size, device)

    def forward(self, x):
        spk1, mem1 = self.lif1(x)
        spk2, mem2 = self.lif2(mem1)
        logits = self.fc(mem2)
        return logits
