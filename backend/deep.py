"""CNN-BiLSTM over real within-flow temporal packet metadata, never tabular pseudo-time."""
import torch
from torch import nn
from torch.nn.utils.rnn import pack_padded_sequence


class CNNBiLSTM(nn.Module):
    def __init__(self,classes):
        super().__init__()
        self.conv=nn.Conv1d(8,24,kernel_size=3,padding=1)
        self.lstm=nn.LSTM(24,24,batch_first=True,bidirectional=True)
        self.head=nn.Linear(48,classes)

    def forward(self,x,lengths):
        x=torch.relu(self.conv(x.transpose(1,2))).transpose(1,2)
        packed=pack_padded_sequence(x,lengths.cpu(),batch_first=True,enforce_sorted=False)
        _,(h,_)=self.lstm(packed)
        return self.head(torch.cat([h[-2],h[-1]],dim=1))
