all:
	gcc ibbe.c -g test.c \
	-lgmp -lpbc -lssl -lcrypto -lm -lpthread \
	-L/usr/local/lib/ -I/usr/local/include/pbc \
	-o test_ibbe.o

cpp:
	g++ -std=c++11 ibbe.c spibbe.cpp tests.cpp admin_api.cpp cloud.cpp serialization.cpp -g main.cpp \
	/usr/local/lib/libcpp_redis.a  /usr/local/lib/libtacopie.a \
	-lgmp -lpbc -lssl -lcrypto -lm -lpthread \
	-L/usr/local/lib/ -I/usr/local/include/pbc \
	-o test_ibbe.o

lib_py:
	gcc -shared -fPIC -g ibbe.c pythonscriptcffi.gen.c -lgmp -lpbc -lssl -lcrypto -lm -lpthread -L/usr/local/lib/ -I/usr/local/include/pbc -o ibbe.so

lib:
	gcc -shared -fPIC -g ibbe.c spibbe.c -lgmp -lpbc -lssl -lcrypto -lm -lpthread -L/usr/local/lib/ -I/usr/local/include/pbc -o libspibbe.so

lib_first:
	gcc -fPIC \
	-c ibbe.c \
	-lgmp -lpbc -lssl -lcrypto -lm -lpthread \
	-L/usr/local/lib/ -I/usr/local/include/pbc \
	-o ibbe.o

lib_dynamic:
	gcc -shared -Wl,-soname,libibbe.so.1 \
	-lm -lpthread \
	-L/usr/local/lib/ -I/usr/local/include/pbc \
	-o libmean.so.1.0.1 ibbe.o -lssl -lcrypto -lgmp -lpbc

full:
	make lib_first && make lib_dynamic
	#&& cp libibbe.so ..

	#gcc -shared  -o libmean.so.1.0.1  calc_mean.o


#x86_64-linux-gnu-gcc -pthread -DNDEBUG -g -fwrapv -O2 -Wall -Wstrict-prototypes -g -fstack-protector-strong -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2 -fPIC -I/usr/local/include/pbc -I/usr/include/python3.5m -c ibbe.c -o ./ibbe.o
#x86_64-linux-gnu-gcc -pthread -shared -Wl,-O1 -Wl,-Bsymbolic-functions -Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-Bsymbolic-functions -Wl,-z,relro -g -fstack-protector-strong -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2 ./ibbe.o -lpython3.5m -o ./ibbe.so
