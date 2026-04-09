import torch
import torch.nn as nn

class SurrogateSpike(torch.autograd.Function):
    @staticmethod
    def forward(ctx, x):
        out = (x > 0).float()
        ctx.save_for_backward(x)
        return out

    @staticmethod
    def backward(ctx, grad_output):
        (x,) = ctx.saved_tensors
        grad = 1.0 / (1 + torch.abs(x))**2
        return grad_output * grad

spike_fn = SurrogateSpike.apply

class LIFLayer(nn.Module):
    def __init__(self, in_features, out_features, tau=0.9):
        super().__init__()
        self.fc = nn.Linear(in_features, out_features)
        self.tau = tau
        self.register_buffer("mem", None)

    def reset_state(self, batch_size, device=None):
        dev = device if device else next(self.fc.parameters()).device
        self.mem = torch.zeros(batch_size, self.fc.out_features, device=dev)

    def forward(self, x):
        cur = self.fc(x)
        self.mem = self.tau * self.mem + cur
        spk = spike_fn(self.mem - 1.0)
        self.mem = self.mem * (1 - spk)
        return spk, self.mem
