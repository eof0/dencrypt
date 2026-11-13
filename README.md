## Need these to compile it
sudo pacman -S gcc libsodium

## Compile it
g++ -std=c++17 -O2 -Wall -Wextra dencrypt.cpp -o dencrypt -lsodium
