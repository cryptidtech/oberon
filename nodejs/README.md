## Build Instructions

### Amazon Linux 2
1. yum update
2. yum install tar gzip gcc git
3. curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
4. source "$HOME/.cargo/env"
5. curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.34.0/install.sh | bash
6. . ~/.nvm/nvm.sh
7. nvm install --lts
8. npm install -g npm@9.5.0
9. git clone https://github.com/cryptidtech/oberon.git
10. cd oberon/nodejs
11. npm install

### Ubuntu
1. apt update
2. apt upgrade -y
3. apt install build-essential pkg-config clang
4. curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
5. source "$HOME/.cargo/env"
6. curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.34.0/install.sh | bash
7. . ~/.nvm/nvm.sh
8. nvm install --lts
9. npm install -g npm@9.5.0
10. git clone https://github.com/cryptidtech/oberon.git
11. cd oberon/nodejs
12. npm install
