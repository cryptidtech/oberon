## Build Instructions

### Amazon Linux 2
1. yum update
1. yum install tar gzip gcc git
1. curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
1. source "$HOME/.cargo/env"
1. curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.34.0/install.sh | bash
1. . ~/.nvm/nvm.sh
1. nvm install --lts
1. npm install -g npm@9.5.0
1. git clone https://github.com/cryptidtech/oberon.git
1. cd oberon/nodejs
1. npm install

### Ubuntu
1. apt update
2. apt upgrade -y
3. apt install build-essential pkg-config clang
1. curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
1. source "$HOME/.cargo/env"
1. curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.34.0/install.sh | bash
1. . ~/.nvm/nvm.sh
1. nvm install --lts
1. npm install -g npm@9.5.0
1. git clone https://github.com/cryptidtech/oberon.git
1. cd oberon/nodejs
1. npm install
