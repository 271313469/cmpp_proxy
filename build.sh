#/bin/bash

cd ./src
make -f Makefile.ismg
make -f Makefile.db
make -f Makefile.log

cp ./ismg_proxy ../bin/
cp ./db_proxy ../bin/
cp ./log_proxy ../bin/
