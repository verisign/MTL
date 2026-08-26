# MTL Mode Demo

<!-- GETTING STARTED -->
## Getting Started
---
### Docker
The Docker image includes Python 3.12.12 and JupyterLab, and is built on top of the pqc_base image. 


To build the image
```bash
docker compose build jupyter
```

To start the container (and JupyterLab)
```bash
docker compose up jupyter 
```

To run JupyterLab using Visual Studio Code, ctrl + click the link in the terminal. To run JupyterLab using a browser, navigate to http://127.0.0.1:8888/lab in your browser.



### Structure
```
├── demo                             # this demo
│   ├── data                         # vectors used in this demo
│   │   └── ...
│   │
│   ├── helper
│   │   ├── mtl_parser.py            # helper functions that parse the full signature into MTL components
│   │   ├── utils.py                 # helper functions that create the signed data and visualize the MTL
│   │   └── verifier.py              # helper functions that perform signature and authentication path validation
│   │
│   ├── mtlmode_demo.ipynb           # jupyter notebook for the MTL Mode demo
|   ├── mldsa_key_sig.ipynb          # jupyter notebook that generates the ML-DSA key pair and creates the ladder signature
|   └── slhdsa_key_sig_gen.ipynb     # jupyter notebook that generates the SLH-DSA key pair and creates the ladder signature
│   │
|   └── README.md
```