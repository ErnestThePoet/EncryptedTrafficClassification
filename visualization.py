import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from utils import *
from matplotlib import pyplot as plt

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei"]
plt.rcParams['axes.unicode_minus'] = False
plt.rcParams['figure.figsize'] = (7, 7)


def pca(data_std: np.ndarray, n_components) -> np.ndarray:
    pca = PCA(n_components=n_components, svd_solver='full')
    pca.fit_transform(data_std)
    return data_std @ pca.components_.T


dataset_qq = rdpcap("./dataset/qq_10k.pcap")
dataset_wx = rdpcap("./dataset/wx_7k5.pcap")
dataset_https = rdpcap("./dataset/https_20k.pcap")

headers_qq = get_tcp_udp_headers(dataset_qq)
headers_wx = get_tcp_udp_headers(dataset_wx)
headers_https = get_tcp_udp_headers(dataset_https)

s = StandardScaler()
std_qq = s.fit_transform(headers_qq)
std_wx = s.fit_transform(headers_wx)
std_https = s.fit_transform(headers_https)

# PCA
pc_qq = pca(std_qq, 10)
pc_wx = pca(std_wx, 10)
pc_https = pca(std_https, 10)

plt.scatter(pc_qq[:, 0], pc_qq[:, 1], c='limegreen', s=0.5, label="qq")
plt.scatter(pc_wx[:, 0], pc_wx[:, 1], c='dodgerblue', s=0.5, label="微信")
plt.scatter(pc_https[:, 0], pc_https[:, 1], c='gold', s=0.5, label="https")
plt.title("PCA投影")
plt.legend()
plt.show()

plt.clf()

# t-SNE
tsne = TSNE(n_components=2, perplexity=30.0, n_iter=1000, random_state=0, verbose=2)
tsne_qq = tsne.fit_transform(std_qq)
tsne_wx = tsne.fit_transform(std_wx)
tsne_https = tsne.fit_transform(std_https)

plt.scatter(tsne_qq[:, 0], tsne_qq[:, 1], c='limegreen', s=0.5, label="qq")
plt.scatter(tsne_wx[:, 0], tsne_wx[:, 1], c='dodgerblue', s=0.5, label="微信")
plt.scatter(tsne_https[:, 0], tsne_https[:, 1], c='gold', s=0.5, label="https")
plt.title("t-SNE投影")
plt.legend()
plt.show()
