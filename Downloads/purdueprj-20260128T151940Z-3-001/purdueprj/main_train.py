import torch
from torch.utils.data import DataLoader

from data.modelnet import ModelNetDataset
from models.pointnet_snn import PointNetSNN
from training.train_loop import train_one_epoch
from training.optimizers import build_optimizer

def main():

    device = 'cuda' if torch.cuda.is_available() else 'cpu'

    # Debug dataset
    ds = ModelNetDataset(root="/content/drive/MyDrive/ModelNet10", split='train')
    dataloader = DataLoader(ds, batch_size=1, shuffle=True)

    model = PointNetSNN(num_classes=10).to(device)
    optimizer = build_optimizer(model)

    for epoch in range(5):
        loss, acc = train_one_epoch(model, dataloader, optimizer, device)
        print(f"Epoch {epoch} | Loss: {loss:.4f} | Acc: {acc:.4f}")

if __name__ == "__main__":
    main()
