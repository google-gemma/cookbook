import torch

def slice_random(points, T=8):
    N = points.shape[0]
    perm = torch.randperm(N)
    return torch.chunk(perm, T)

def slice_radial(points, T=8):
    center = points.mean(dim=0)
    dist = torch.norm(points - center, dim=1)
    perm = torch.argsort(dist)   # inner → outer
    return torch.chunk(perm, T)

def slice_pca(points, T=8):
    X = points - points.mean(dim=0)
    U, S, V = torch.pca_lowrank(X)
    pc1 = V[:, 0]
    proj = X @ pc1
    perm = torch.argsort(proj)
    return torch.chunk(perm, T)
