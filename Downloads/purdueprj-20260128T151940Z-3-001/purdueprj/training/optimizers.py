import torch

def build_optimizer(model, lr=1e-3, weight_decay=1e-4):
    return torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
