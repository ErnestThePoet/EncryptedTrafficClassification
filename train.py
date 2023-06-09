import numpy as np
from matplotlib import pyplot as plt
import torch.optim
from torch import nn
from torch.utils.data.dataset import Dataset
from torch.utils.data import DataLoader
from scapy.all import *
from utils import get_tcp_udp_slices
from model import TCDNN


class PcapDataset(Dataset):
    def __init__(self, file_paths, classes):
        headers = [get_tcp_udp_slices(rdpcap(x)) for x in file_paths]
        self.packets = torch.from_numpy(np.concatenate(headers)).type(torch.float)
        expanded_classes = [np.empty(len(x)) for x in headers]
        for i, ie in enumerate(classes):
            expanded_classes[i].fill(ie)
        self.classes = torch.from_numpy(np.concatenate(expanded_classes)).type(torch.long)

        # Shuffle
        for i in range(len(self.classes)):
            index1 = np.random.randint(0, len(self.classes))
            index2 = np.random.randint(0, len(self.classes))

            if index1 == index2:
                continue

            temp = self.packets[index1]
            self.packets[index1] = self.packets[index2]
            self.packets[index2] = temp

            temp = self.classes[index1]
            self.classes[index1] = self.classes[index2]
            self.classes[index2] = temp

    def __len__(self):
        return len(self.packets)

    def __getitem__(self, item):
        return self.packets[item], self.classes[item]


CLASS_QQ = 0
CLASS_WX = 1
CLASS_HTTPS = 2

dataset_train = PcapDataset(["./dataset/qq_train.pcap",
                             "./dataset/wx_train.pcap",
                             "./dataset/https_train.pcap"],
                            [CLASS_QQ, CLASS_WX, CLASS_HTTPS])

dataset_test = PcapDataset(["./dataset/qq_test.pcap",
                            "./dataset/wx_test.pcap",
                            "./dataset/https_test.pcap"],
                           [CLASS_QQ, CLASS_WX, CLASS_HTTPS])

batch_size = 64

dataloader_train = DataLoader(dataset_train, batch_size)
dataloader_test = DataLoader(dataset_test, batch_size)

device = "cuda"

model = TCDNN().to(device)
loss_fn = nn.CrossEntropyLoss()
optimizer = torch.optim.SGD(model.parameters(), lr=1e-03)


def train(dataloader: DataLoader,
          model: nn.Module,
          loss_fn: nn.Module,
          optimizer: torch.optim.Optimizer):
    model.train()
    for i, (x, y) in enumerate(dataloader):
        x, y = x.to(device), y.to(device)

        pred = model(x)

        loss = loss_fn(pred, y)

        loss.backward()
        optimizer.step()
        optimizer.zero_grad()

        # if i % 100 == 0:
        #     print(f"Loss: {loss.item():>5f} {i * len(x)}/{len(dataloader.dataset)}")


accuracies = []
losses = []


def test(dataloader: DataLoader,
         model: nn.Module,
         loss_fn: nn.Module):
    model.eval()
    loss = 0
    correct = 0

    with torch.no_grad():
        for (x, y) in dataloader:
            x, y = x.to(device), y.to(device)

            pred = model(x)

            loss += loss_fn(pred, y).item()

            correct += (pred.argmax(1) == y).type(torch.float).sum().item()

    loss /= len(dataloader)
    correct /= len(dataloader.dataset)

    accuracies.append(correct)
    losses.append(loss)

    print(f"Test Accuracy: {100 * correct:>0.1f}% | Test Loss: {loss}")


epoch_count = 300
for i in range(epoch_count):
    print(f"Epoch {i + 1}")
    train(dataloader_train, model, loss_fn, optimizer)
    test(dataloader_test, model, loss_fn)

torch.save(model.state_dict(), "./model/tcann.pth")

plt.plot(np.arange(0, epoch_count), accuracies, c="royalblue")
plt.title("Accuracy")
plt.xlabel("Epoch")
plt.ylabel("Accu")
plt.show()

plt.plot(np.arange(0, epoch_count), losses, c="firebrick")
plt.title("Loss")
plt.xlabel("Epoch")
plt.ylabel("Loss")
plt.show()
