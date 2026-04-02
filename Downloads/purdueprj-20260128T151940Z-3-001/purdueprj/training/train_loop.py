import torch
from torch.utils.data import DataLoader

from training.loss_functions import ce_loss_final, ce_loss_aux
from training.metrics import accuracy
from data.slicing import slice_radial, slice_pca, slice_random


def train_one_epoch(model, dataloader, optimizer, device, num_slices=8, aux_weight=0.2):
    model.train()

    total_loss = 0.0
    total_acc = 0.0
    count = 0

    for pts, labels in dataloader:

        pts = pts.to(device)            # [B,1024,3]
        labels = labels.to(device)

        B = pts.size(0)

        model.reset_state(batch_size=B, device=device)

        # Choose slicing method (radial is stable)
        slice_idx = slice_radial(pts[0], T=num_slices)  # idx chunks for sample 0
        # For batch > 1, you'd compute slicing per-sample, but debug with batch=1.

        logits_all = []

        # Sequential slice processing
        for t in range(num_slices):
            idx = slice_idx[t]  # indices for this slice
            pts_slice = pts[:, idx, :]  # [B, slice_size, 3]

            logits_t = model.forward_step(pts_slice)
            logits_all.append(logits_t)

        # Compute loss
        loss = ce_loss_final(logits_all[-1], labels)
        loss += ce_loss_aux(logits_all, labels, aux_weight)

        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        # Track stats
        total_loss += loss.item()
        total_acc += accuracy(logits_all[-1], labels)
        count += 1

    return total_loss / count, total_acc / count
