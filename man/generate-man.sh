#!/bin/bash

# Generate the manpage
# Copyright 2016 Joao Eriberto Mota Filho <eriberto@eriberto.pro.br>
# This file is under BSD-3-Clause

P_DATA="05 Feb 2020"
P_NAME=packit
P_VERSION=1.7
P_MANLEVEL=8
P_DESCRIPT="Network packet generator and capture tool "

TEST=$(txt2man -h 2> /dev/null)

[ ! "$TEST" ] && { echo "ERROR: You need install txt2man program."; exit 1; }

[ -e $P_NAME.txt ] || { echo "ERROR: $P_NAME.txt not found."; exit 1; }

txt2man -d "$P_DATA" -t $P_NAME -r $P_NAME-$P_VERSION -s $P_MANLEVEL -v "$P_DESCRIPT" $P_NAME.txt > $P_NAME.$P_MANLEVEL
