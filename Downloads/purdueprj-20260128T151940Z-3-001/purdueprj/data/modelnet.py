import os
import torch
import numpy as np
from torch.utils.data import Dataset

class ModelNetDataset(Dataset):
    def __init__(self, root, num_points=1024, split='train'):
        self.root = root
        self.num_points = num_points
        self.split = split

        self.files = self._scan_files()
        self.data, self.labels = self._load_all()

    def _scan_files(self):
        items = []
        for class_name in sorted(os.listdir(self.root)):
            class_path = os.path.join(self.root, class_name, self.split)
            if not os.path.isdir(class_path):
                continue
            label = sorted(os.listdir(self.root)).index(class_name)
            for f in os.listdir(class_path):
                if f.endswith('.npy') or f.endswith('.txt'):
                    items.append((os.path.join(class_path, f), label))
        return items

    def _load_points(self, path):
        if path.endswith('.npy'):
            pts = np.load(path).astype(np.float32)
        else:
            pts = np.loadtxt(path).astype(np.float32)
        return pts

    def _load_all(self):
        all_pts, all_labels = [], []
        for path, label in self.files:
            pts = self._load_points(path)

            if pts.shape[0] >= self.num_points:
                idx = np.random.choice(pts.shape[0], self.num_points, replace=False)
                pts = pts[idx]
            else:
                pad = self.num_points - pts.shape[0]
                pts = np.vstack([pts, pts[:pad]])

            all_pts.append(pts)
            all_labels.append(label)

        return np.array(all_pts), np.array(all_labels)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        pts = self.data[idx]
        label = self.labels[idx]
        np.random.shuffle(pts)
        return torch.tensor(pts, dtype=torch.float32), torch.tensor(label, dtype=torch.long)
