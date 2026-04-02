import torch
import torch.nn.functional as F

def ce_loss_final(logits_T, labels):
    return F.cross_entropy(logits_T, labels)

def ce_loss_aux(logits_all, labels, aux_weight=0.2):
    """
    logits_all: list of logits at each timestep [logits_1, ..., logits_T]
    """
    loss = 0.0
    T = len(logits_all)
    for t in range(T - 1):  # exclude final
        loss += F.cross_entropy(logits_all[t], labels) * aux_weight
    return loss
