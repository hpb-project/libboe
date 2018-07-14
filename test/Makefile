rstest:
	gcc -g rstest.c ../rs.c -I ../ -o rstest

msgctest:
	gcc -g msgctest.c ../common.c ../aq.c ../rs.c ../msgc.c -I .. -o msgctest -lpthread

axutest:
	gcc -g ../common.c ../aq.c ../doAXU.c ../serror.c ../msgc.c ../rs.c ../axu_connector.c axutest.c  -I .. -lpthread -o axutest
