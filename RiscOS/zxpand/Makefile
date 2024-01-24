PACKAGE_DATA_DIR?=$(PREFIX)/data
CXXFLAGS=-O3 -Wall -DPACKAGE_DATA_DIR=\"$(PACKAGE_DATA_DIR)\" -Wno-trigraphs

CXX=g++ -static

SOURCES = zxpand_emu.cpp zxpandclass.cpp smbsd.cpp zxpandcom.cpp usart.cpp zxpandcore.cpp js.cpp wildcard.cpp ff.cpp
OBJECTS=$(patsubst %.cpp, %.o, $(SOURCES))

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

libzxpand.a: $(OBJECTS)
	$(AR) $(ARFLAGS) $@ $(OBJECTS)
	ranlib libzxpand.a

clean:
	rm -f *.o *.a *~
