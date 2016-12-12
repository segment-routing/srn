#!/bin/bash -x
aclocal
autoheader
automake --add-missing
autoconf
./configure
