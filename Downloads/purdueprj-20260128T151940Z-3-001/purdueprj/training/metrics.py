import torch

def accuracy(logits, labels):
    preds = logits.argmax(dim=1)
    return (preds == labels).float().mean().item()

def margin(logits):
    probs = logits.softmax(dim=-1)
    top2 = probs.topk(2, dim=-1).values
    return (top2[:, 0] - top2[:, 1]).mean().item()
