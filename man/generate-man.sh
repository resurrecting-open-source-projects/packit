#!/bin/bash

# Generate the manpage
# Copyright 2016 Joao Eriberto Mota Filho <eriberto@eriberto.pro.br>
# This file is under BSD-3-Clause

P_DATA="22 May 2016"
P_NAME=packit
P_VERSION=1.1
P_MANLEVEL=8
P_DESCRIPT="Packet analysis and injection tool"

[ -e $P_NAME.txt ] || { echo "$P_NAME.txt not found"; exit 1; }

txt2man -d "$P_DATA" -t $P_NAME -r $P_NAME-$P_VERSION -s $P_MANLEVEL -v "$P_DESCRIPT" $P_NAME.txt > $P_NAME.$P_MANLEVEL
