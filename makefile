all:
	g++ -std=c++0x admin_app.cpp \
	/usr/local/lib/libcpp_redis.a  /usr/local/lib/libtacopie.a \
	-lpthread -lgmp -lpbc -lssl -lcrypto -lm \
	-L/usr/local/lib/ -L./pbc_ibbe -I/usr/local/include/pbc \
	-o admin.app -libbe

	#-L./pbc_ibbe pbc_ibbe/libibbe.so.1

	# -L. -libbe

#-L./pbc_ibbe -libbe

#-L./pbc_ibbe -lspibbe pbc_ibbe/libspibbe.so \

# pbc_ibbe/libspibbe.a

#	g++ -std=c++0x admin_app.cpp /usr/local/lib/libcpp_redis.a /usr/local/lib/libtacopie.a pbc_ibbe/ibbe.so -lpthread -I/usr/local/include/pbc -o test.out
#-Wl,-Bstatic pbc_ibbe/libspibbe.a \
#-Wl,-Bdynamic
