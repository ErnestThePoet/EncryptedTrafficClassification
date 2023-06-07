from torch import nn


# Traffic Classification Artificial Neural Network
class TCANN(nn.Module):
    def __init__(self):
        super(TCANN, self).__init__()
        self.mlp = nn.Sequential(
            nn.Linear(100, 90),
            nn.ReLU(),
            nn.Linear(90, 70),
            nn.ReLU(),
            nn.Linear(70, 50),
            nn.ReLU(),
            nn.Linear(50, 30),
            nn.ReLU(),
            nn.Linear(30, 3),
            nn.Softmax(dim=1)
        )

    def forward(self, x):
        return self.mlp(x)
