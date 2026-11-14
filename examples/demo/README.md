# MTL for DNSSEC Demo
This demo interactively walks through MTL for DNSSEC on both authoritative servers and resolvers. 

<!-- GETTING STARTED -->
### Docker
The Docker image includes Python 3.12.12 and JupyterLab, and is built on top of the pqc_base image. 


To build the image
```bash
docker compose build
```

To start the container (and JupyterLab)
```bash
docker compose up jupyter 
```

To run JupyterLab using Visual Studio Code, ctrl + click the link in the terminal. To run JupyterLab using a browser, navigate to http://127.0.0.1:8888/lab in your browser.



### Structure
```
├── demo                                         # this demo
│   ├── data                                     # vectors used in this demo
│   │   ├── incrsig                              # vectors used in 3-incremental_signing.ipynb
|   |   └── ...
│   │
│   ├── helper
│   │   ├── builder.py                           # helper functions that build a MTL using a predefined node set
│   │   ├── ladder_updater.py                    # helper functions that update a ladder
│   │   ├── mtl_parser.py                        # helper functions that parse the full signature
│   │   ├── signer.py                            # helper functions that generate key pairs and perform signing
│   │   ├── utils.py                             # helper functions that create the signed data and visualize the MTL
│   │   └── verifier.py                          # helper functions that perform verification
│   │
│   ├── 1-build_a_mtl.ipynb                      # jupyter notebook that builds a MTL using a predefined node set
|   ├── 2-verify_a_fullsig.ipynb                 # jupyter notebook that performs full signature verification
│   ├── 3-incremental_signing.ipynb              # jupyter notebook that performs incremental signing
|   ├── 4-query_with_sigtag.ipynb                # jupyter notebook that uses the SigTag EDNS(0) option
|   ├── 5-sigtag_deduplication.ipynb             # jupyter notebook that demonstrates deduplication enabled by SigTag
|   |
|   └── README.md
```