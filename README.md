## Encrypted Traffic Classification
A simple DNN-based encrypted traffic classifier.  
The model takes the first 100 bytes of a packet(starting from eth header, pad with 0s if packet length is <100), which is classified into QQ/WeChat/HTTPS. Packets are captured with `scapy` on the fly.  
On our dataset, the model is trained to have an accuracy of 92.1%.