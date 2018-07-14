all:rstest msgctest axutest tstest mkimage

rstest:
	gcc -g rstest.c ../rs.c -I ../ -o rstest

msgctest:
	gcc -g msgctest.c ../common.c ../aq.c ../rs.c ../msgc.c -I .. -o msgctest -lpthread

axutest:
	gcc -g ../common.c ../aq.c ../doAXU.c ../serror.c ../msgc.c ../rs.c ../axu_connector.c axutest.c  -I .. -lpthread -o axutest

tstest:
	gcc -g ../common.c ../aq.c ../doAXU.c ../serror.c ../msgc.c ../rs.c ../axu_connector.c tstest.c  -I .. -lpthread -o tstest

mkimage:
	gcc mkimage.c ../axu_connector.c ../common.c ../serror.c -I.. -o mkimage

clean:
	rm rstest msgctest axutest tstest mkimage
