FROM chainflag/solidctf:1.0.0

WORKDIR /ctf

COPY ./contracts /ctf/contracts
COPY ./challenge.yml /ctf/challenge.yml
COPY ./run.sh /run.sh

RUN chmod +x /run.sh

# pre-install solc
RUN python3 -c 'import os; from brownie import project; from solcx import install; default = os.getenv("SOLC_DOWNLOAD_BASE", "https://cdn.jsdelivr.net/gh/ethereum/solc-bin@latest").rstrip("/"); install.BINARY_DOWNLOAD_BASE = default + "/{}-amd64/{}"; project.load(".")'

# Change it if necessary: docker run -e WEB3_PROVIDER_URI="<your_rpc_url>"
ENV WEB3_PROVIDER_URI="http://106.15.138.99:8545/"

CMD ["/run.sh"]