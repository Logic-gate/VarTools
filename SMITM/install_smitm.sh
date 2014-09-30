#!/bin/bash


echo 'Silent MITM'

sudo mv SMITM/smitm /usr/local/bin
sudo mv SMITM/smitm-stop /usr/local/bin
sudo mv SMITM/parselog /usr/local/bin
sudo mv SMITM/log_ex /usr/local/bin
chmod +x /usr/local/bin/parselog
chmod +x /usr/local/bin/log_ex

echo 'done'

exit 0
