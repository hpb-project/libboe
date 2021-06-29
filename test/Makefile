all:rstest axutest tstest mkimage boetest fpgatest bawriteinfo getinfo boereg_test boeupdate update_record_info genidtest multitest

rstest:
	gcc -g rstest.c ../rs.c -I ../ -o rstest

#msgctest:
#	gcc -g msgctest.c ../common.c ../aq.c ../rs.c ../msgc.c -I .. -o msgctest -lpthread

axutest:
	gcc -g ../common.c ../aq.c ../doAXU.c ../serror.c ../msgc.c ../rs.c ../axu_connector.c axutest.c  -I .. -lpthread -o axutest

tstest:
	gcc -g ../common.c ../aq.c ../doAXU.c ../serror.c ../msgc.c ../rs.c ../axu_connector.c tstest.c  -I .. -lpthread -o tstest

mkimage:
	gcc mkimage.c ../axu_connector.c ../common.c ../serror.c -I.. -o mkimage

boetest:
	gcc -g  boetest.c -I ../ -L ../lib --static -lboe -lpthread -o boetest

multitest:
	gcc -g  multipacket.c -I ../ -L ../lib --static -lboe -lpthread -o multitest

fpgatest:
	gcc -g  fpgatest.c -I ../ -L ../lib --static -lboe -lpthread -o fpgatest

boeupdate:
	gcc -g  boeupdate.c -I ../ -L ../lib --static -lboe -lpthread -o boeupdate

bawriteinfo:
	gcc advance_writeinfo.c -I ../ -L ../lib --static  -lboe -g -o bawriteinfo -lpthread

getinfo:
	gcc getinfo.c -I ../ -L ../lib --static  -lboe -g -o getinfo -lpthread
boereg_test:
	gcc boereg_test.c -g -I ../ -L ../lib --static -lboe -o boereg_test -lpthread

update_record_info:
	gcc update_record_info.c -I ../ -L ../lib --static -lboe -g -o update_record_info -lpthread

genidtest:
	gcc ../sha3.c ../genid.c genidtest.c -I ../ -o genidtest

clean:
	rm rstest axutest tstest mkimage boetest fpgatest bawriteinfo getinfo boeupdate boereg_test update_record_info genidtest multitest
