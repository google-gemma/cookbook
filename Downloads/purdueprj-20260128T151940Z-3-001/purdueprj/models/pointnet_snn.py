import torch
import torch.nn as nn

from models.pointnet_backbone import PointNetBackbone
from models.temporal_snn import TemporalSNN


class PointNetSNN(nn.Module):
    """
    Full SNN-PointNet model:
        - Per-point spiking MLP (PointNet backbone)
        - Slice pooling (mean pooling)
        - Temporal SNN accumulator
        - Final classifier (inside temporal SNN module)
    """

    def __init__(self,
                 point_dims=[64, 128, 256],   # per-point feature sizes
                 temporal_dim=256,            # temporal SNN hidden dimension
                 num_classes=10):             # ModelNet10 for debugging
        super().__init__()

        self.backbone = PointNetBackbone(hidden_dims=point_dims)
        self.temporal = TemporalSNN(dim=temporal_dim)
        self.num_classes = num_classes

    def reset_state(self, batch_size, device=None):
        """Reset membrane states before each new sample."""
        self.backbone.reset_state(batch_size, device)
        self.temporal.reset_state(batch_size, device)

    def forward_step(self, pts_slice):
        """
        Process a single slice of points.
        pts_slice: [B, n_points, 3]

        Returns:
            logits_t : [B, num_classes]
        """

        # 1. Per-point spiking MLP
        per_point_feat = self.backbone(pts_slice)   # [B, M, 256]

        # 2. Mean pooling across slice points → slice embedding
        slice_feat = per_point_feat.mean(dim=1)     # [B, 256]

        # 3. Feed slice embedding into temporal SNN
        logits_t = self.temporal(slice_feat)        # [B, num_classes]

        return logits_t
