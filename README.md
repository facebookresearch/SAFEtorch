# SAFEtorch

Pytorch implemenation of the **SAFE** neural network.

**SAFE** can be used to produce dense representations (*i.e.*, embeddings) for arbitrary binary functions. It works for both the X86 and ARM architectures.

See our paper on arXiv: [https://arxiv.org/abs/1811.05296](https://arxiv.org/abs/1811.05296)

If you use this code, please cite:
```bibtex
@inproceedings{massarelli2018safe,
  title={SAFE: Self-Attentive Function Embeddings for Binary Similarity},
  author={Massarelli, Luca and Di Luna, Giuseppe Antonio and Petroni, Fabio and Querzoni, Leonardo and Baldoni, Roberto},
  booktitle={Proceedings of 16th Conference on Detection of Intrusions and Malware & Vulnerability Assessment (DIMVA)},
  year={2019}
}
```

## Quickstart

### 1. Create conda environment and install requirements

(optional) It might be a good idea to use a separate conda environment. It can be created by running:
```
conda create -n safe37 -y python=3.7 && conda activate safe37
pip install -r requirements.txt
```

### 2. Download the model

Download the model weights from http://dl.fbaipublicfiles.com/SAFEtorch/model.tar.gz

```bash
wget http://dl.fbaipublicfiles.com/SAFEtorch/model.tar.gz
tar -xzvf model.tar.gz
rm model.tar.gz
```

### 3. Use SAFE
Please refer to this notebook [test.ipynb](test.ipynb)

Or try out this script [test.py](test.py) to get all the function embeddings of the input binary.

```bash
python test.py <binary_path>
```

## Acknowledgements
* SAFE implementation in tensorflow (https://github.com/gadiluna/SAFE) 
* YARASAFE: Automatic Binary Function Similarity Checks with Yara (https://github.com/lucamassarelli/yarasafe) 


## Licence

SAFEtorch is licensed under the MIT license. The text of the license can be found [here](LICENSE).
