#!/bin/bash 

source=.
docker run -it -v $source:/nfr nfrbuilder bash 
