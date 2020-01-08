#!/bin/bash

echo "-> INSTALLING THE PREREQUISITS FOR WOLFSSL, MAKE, AUTOCONF, GCC"
sudo apt-get install make autoconf gcc


echo "-> CONFIGURING WOLFSSL AND INSTALLING"
cd wolfssl-4.3.0
./configure && make && sudo make install
sudo ldconfig


echo "------------------------------------------------"
echo "ENJOY YOUR NEW LIB WOLFSSL"
echo "USE IN GCC WITH -lwolfssl"
