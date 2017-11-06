CC             := gcc
CXX            := g++-5
SHELL          := /bin/bash
SGX            := 0

is_sgx         :=$(SGX:0=)
SrcDir         := src
SGX_COMMONDIR  := $(realpath ../../sgx_common)
PBCRootDir     := $(realpath ../pbc-0.5.14)
GMPRootDir     := $(realpath ../gmp-6.1.2)

SgxToken       := sgx
NativeToken    := ntv

SharedCompFlags := -m64
CFlags          := -std=c11
CXXFlags        := -std=c++11
Natv_CFlags     := $(SharedCompFlags) $(CFlags)
Enclave         := grpshr
TARGET          := $(Enclave)
NatvObjs        := $(TARGET).o
EnclaveName     := enclave_$(Enclave)
ExternalLibs    := pbc gmp crypto 

IBBEDir     := ../pbc_ibbe
IBBEC       := $(notdir $(wildcard $(IBBEDir)/sgx_*.c))
IBBECXX     := $(notdir $(wildcard $(IBBEDir)/sgx_*.cpp))

BuildToken      := $(if $(is_sgx),$(SgxToken),$(NativeToken))
NtvGMPDir       := $(GMPRootDir)/build-$(NativeToken)
NtvPBCDir       := $(PBCRootDir)/build-$(NativeToken)
SgxGMPDir       := $(GMPRootDir)/build-$(SgxToken)
SgxPBCDir       := $(PBCRootDir)/build-$(SgxToken)
OSSLDir         := $(realpath ../../intel-sgx-ssl)
SGXOSSLLDir     := $(OSSLDir)/lib64/release/
SGXOSSLIDir     := $(OSSLDir)/include/
SGXOpenSSLLib   := $(SGXOSSLLDir)/libsgx_tsgxssl_crypto.a
LibsConfigFlags := --with-pic=yes --enable-shared=no
App_Lib_Dirs    := $(addsuffix /.libs, $(NtvGMPDir) $(NtvPBCDir))
App_Libs        := $(ExternalLibs)

BinDir  := bin-$(BuildToken)
ObjDir  := obj-$(BuildToken)

ifeq ($(SGX),1)
ExtLibs              += $(SgxGMPDir)/.libs/libgmp.a \
                        $(SgxPBCDir)/.libs/libpbc.a  $(SGXOpenSSLLib)
IBBEC                := $(IBBEC:%.c=%_t.o)
IBBECXX              := $(IBBECXX:%.cpp=%_t.o)
IBBEObjs             := $(IBBEC) $(IBBECXX)
EnclCommonObjs       := libc_proxy_t.o file_mock_t.o sdk_deprecated_t.o \
                        sgx_cryptoall_t.o
EnclAllObjs          := $(EnclaveName)_t.o ecalls_$(Enclave)_t.o \
                        $(EnclCommonObjs) $(IBBEObjs)
SGX_SDK              := /opt/intel/sgxsdk
SGX_LIBRARY_PATH     := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER   := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R          := $(SGX_SDK)/bin/x64/sgx_edger8r
Trts_Library_Name    := sgx_trts
Service_Library_Name := sgx_tservice
App_Lib_Dirs         += $(SGX_LIBRARY_PATH) 
App_Libs             += sgx_uae_service sgx_urts 
SharedCompFlags      += -DENABLE_SGX -DSGX_OPENSSL
NatvIncludeDirs      += $(SGX_SDK)/include
NatvObjs             += ocalls.o tests_u.o sgx_spibbe_u.o sgx_crypto_u.o \
                        sgx_serialize_u.o sgx_ibbe_u.o
NatvObjs             := $(filter-out $(EnclAllObjs), $(NatvObjs)) \
	                    $(EnclaveName)_u.o
NatvCommonObjs       := $(ObjDir)/sgx_initenclave_u.o $(ObjDir)/sgx_errlist_u.o
Enclave_Lib_Dirs     := $(SGX_LIBRARY_PATH) $(dir $(ExtLibs))
Enclave_Libs         := sgx_tsgxssl_crypto sgx_tsgxssl
Enclave_SDK_Libs     := -Wl,--whole-archive \
                        -l$(Trts_Library_Name) \
                        -Wl,--no-whole-archive \
                        -Wl,--start-group \
                             $(addprefix -l, sgx_tstdc sgx_tstdcxx sgx_tcrypto \
                                             sgx_tsetjmp \
                                             $(Service_Library_Name) ) \
                        -Wl,--end-group
Enclave_Link_Flags   := $(addprefix -L, $(Enclave_Lib_Dirs)) \
                        $(addprefix -l, $(Enclave_Libs)) \
                        $(Enclave_SDK_Libs)
EnclaveLFlags := -Wl,--no-undefined -nostdlib \
	-nodefaultlibs -nostartfiles $(Enclave_Link_Flags)  \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=$(SrcDir)/$(EnclaveName).lds \
    $(addprefix -l, $(ExternalLibs) sgx_tstdc)
SharedEnclFlags := -DENCLAVED
SharedEnclFlags += $(SharedCompFlags) -nostdinc -fvisibility=hidden \
	               -fpie -fstack-protector -fno-builtin-printf
Encl_CFlags     := $(SharedEnclFlags) $(CFlags) \
                   -Wno-implicit-function-declaration 
Encl_CXXFlags   := $(SharedEnclFlags) $(CXXFlags) -nostdinc++
Enclave_IncDirs := $(SGX_SDK)/include/stlport $(SrcDir) $(SGX_SDK)/include \
                   $(SGX_SDK)/include/tlibc $(SGX_COMMONDIR) \
                   $(PBCRootDir)/include $(SgxGMPDir) $(SGXOSSLIDir)
Encl_Include    := $(addprefix -I, $(Enclave_IncDirs) $(IBBEDir))
EnclAllObjs     := $(addprefix $(ObjDir)/,$(EnclAllObjs))
LibsConfigFlags += --enable-sgx
all: $(BinDir)/$(TARGET) $(BinDir)/$(TARGET).signed.so
$(addprefix $(ObjDir)/,server_protocol.o $(TARGET).o): $(SrcDir)/$(EnclaveName)_u.c
$(ObjDir)/query_manager.o : $(SrcDir)/$(EnclaveName)_t.c
$(ObjDir)/$(EnclaveName)_t.o : $(SgxGMPDir)/gmp.h
else
IBBEC          := $(IBBEC:%.c=%_u.o)
IBBECXX        := $(IBBECXX:%.cpp=%_u.o)
IBBEObjs       := $(IBBEC) $(IBBECXX)
NatvObjs       += ecalls_$(Enclave).o $(IBBEObjs)
LDFLAGS        := -lcrypto -lcrypto++
all: $(BinDir)/$(TARGET)
endif

NatvCommonObjs  += $(addprefix $(ObjDir)/, sgx_cryptoall_u.o)
Natv_CXXFlags   := $(SharedCompFlags) $(CXXFlags)
NatvIncludeDirs += $(SrcDir) $(SGX_COMMONDIR) $(PBCRootDir)/include/ \
                   $(GMPRootDir)/build-ntv/ ../pbc_ibbe
Natv_Include   := $(addprefix -I, $(NatvIncludeDirs))
App_Link_Flags := $(addprefix -L, $(App_Lib_Dirs)) \
                  $(addprefix -l, $(App_Libs)) 
NatvAllObjs    += $(addprefix $(ObjDir)/, $(NatvObjs)) $(NatvCommonObjs)

ObjSuffix    := $(if $(is_sgx),t,u)
CompString   := $(if $(is_sgx),Encl,Natv)
CompCFlags   := $(if $(is_sgx),${Encl_CFlags},${Natv_CFlags})
CompCXXFlags := $(if $(is_sgx),${Encl_CXXFlags},${Natv_CXXFlags})
CompInclude  := $(if $(is_sgx),${Encl_Include},${Natv_Include})
IBBEC    := $(addprefix $(ObjDir)/, $(IBBEC))
IBBECXX  := $(addprefix $(ObjDir)/, $(IBBECXX))
IBBEObjs := $(addprefix $(ObjDir)/, $(IBBEObjs))
EnclCommonObjs := $(addprefix $(ObjDir)/, $(EnclCommonObjs))
EnclGenericComp := $(filter-out $(ObjDir)/$(EnclaveName)_t.o $(IBBEObjs) $(EnclCommonObjs), $(EnclAllObjs))

$(ObjDir)/$(TARGET).o : $(NtvGMPDir)/gmp.h

############## COMMON ##########################################################
$(IBBEC) : $(ObjDir)/%_$(ObjSuffix).o : $(IBBEDir)/%.c
	@${CC} -c $< -o $@ ${CompCFlags} ${CompInclude}
	@echo -e "CC ($(CompString))\t<=\t$<"

$(IBBECXX) : $(ObjDir)/%_$(ObjSuffix).o : $(IBBEDir)/%.cpp
	@${CXX} -c $< -o $@ ${CompCXXFlags} ${CompInclude}
	@echo -e "CXX ($(CompString))\t<=\t$<"
############## UNTRUSTED #######################################################
$(BinDir)/$(TARGET): ${NatvAllObjs} ${NtvExtLibs} | $(BinDir)
	@${CXX} $^ -o $@ ${App_Link_Flags} ${LDFLAGS}
	@echo -e "LINK (App)\t=>\t$@"

$(ObjDir)/%.o : $(SrcDir)/%.c | $(ObjDir)
	@${CC} ${Natv_CFlags} ${Natv_Include} -c $< -o $@
	@echo -e "CC (App)\t<=\t$<"

$(ObjDir)/%.o : $(SrcDir)/%.cpp | $(ObjDir)
	@${CXX} ${Natv_CXXFlags} ${Natv_Include} -c $< -o $@
	@echo -e "CXX (App)\t<=\t$<"

$(ObjDir)/%_u.o : $(IBBEDir)/%.c | $(ObjDir)
	@${CC} ${Natv_CFlags} ${Natv_Include} -c $< -o $@
	@echo -e "CC (App)\t<=\t$<"

$(ObjDir)/%_u.o : $(IBBEDir)/%.cpp | $(ObjDir)
	@${CXX} ${Natv_CXXFlags} ${Natv_Include} -c $< -o $@
	@echo -e "CXX (App)\t<=\t$<"

$(SrcDir)/$(EnclaveName)_u.c : $(SrcDir)/$(EnclaveName).edl $(SGX_EDGER8R)
	@cd $(dir $@) && $(SGX_EDGER8R) --untrusted ../$< --search-path ../$(dir $<) --search-path $(SGX_SDK)/include
	@echo -e "EDGER (App)\t=>\t$@"

$(NatvCommonObjs) : $(ObjDir)/%_u.o : $(SGX_COMMONDIR)/%.cpp | $(ObjDir)
	@${CXX} -c $< -o $@ ${Natv_CXXFlags} ${Natv_Include}
	@echo -e "CXX (App)\t<=\t$<"
############## TRUSTED #########################################################
$(BinDir)/$(TARGET).signed.so : %.signed.so : %.so
	@$(SGX_ENCLAVE_SIGNER) sign -enclave $< -config $(SrcDir)/$(EnclaveName).config.xml -out $@ -key $(SrcDir)/enclave-key.pem
	@echo -e "SIGN (Enclave)\t=>\t$@"

$(BinDir)/$(TARGET).so : $(EnclAllObjs)
	@$(CXX) $^ -o $@ $(EnclaveLFlags)
	@echo -e "LINK (Enclave)\t=>\t$@"

$(SrcDir)/$(EnclaveName)_t.c : $(SrcDir)/$(EnclaveName).edl $(SGX_EDGER8R)
	@cd $(dir $@) && $(SGX_EDGER8R) --trusted ../$< --search-path ../$(dir $<) --search-path $(SGX_SDK)/include
	@echo -e "EDGER (Enclave)\t=>\t$@"

$(ObjDir)/$(EnclaveName)_t.o : $(SrcDir)/$(EnclaveName)_t.c
	@${CC} -c $< -o $@ ${Encl_CFlags} ${Encl_Include} 
	@echo -e "CC (Enclave)\t<=\t$<"

$(ObjDir)/%_t.o : $(SGX_COMMONDIR)/libc_mock/%.c
	@${CC} -c $< -o $@ ${Encl_CFlags} ${Encl_Include} 
	@echo -e "CC (Enclave)\t<=\t$<"

$(ObjDir)/%_t.o : $(SGX_COMMONDIR)/libc_mock/%.cpp
	@${CXX} -c $< -o $@ ${Encl_Include} ${Encl_CXXFlags}
	@echo -e "CXX (Enclave)\t<=\t$<"

$(ObjDir)/%_t.o : $(SGX_COMMONDIR)/%.cpp
	@${CXX} -c $< -o $@ ${Encl_Include} ${Encl_CXXFlags}
	@echo -e "CXX (Enclave)\t<=\t$<"

$(EnclGenericComp) : $(ObjDir)/%_t.o : $(SrcDir)/%.cpp
	${CXX} -c $< -o $@ ${Encl_Include} ${Encl_CXXFlags}
	@echo -e "CXX (Enclave)\t<=\t$<"
################################################################################
%/libpbc.a : %/libgmp.a $(PBCRootDir)/configure
	echo "------ $<"
	exit -1
	rm -rf $(PBCDir) && mkdir -p $(PBCDir) && cd $(PBCDir) && LDFLAGS="-L$(GMPDir)/.libs" CPPFLAGS="-I$(PBCRootDir)/include -I$(GMPDir)" ../configure $(LibsConfigFlags) && make

$(PBCRootDir)/configure:
	cd $(PBCRootDir) && ./setup

%/.libs/libgmp.a : %/gmp.h
	cd $(dir $<) && make

$(GMPRootDir)/build-$(SgxToken)/gmp.h :
	rm -rf $(GMPDir) && mkdir -p $(GMPDir) && cd $(GMPDir) && ../configure $(LibsConfigFlags) && sed -i '39,42{s/^\/\///}' gmp.h

$(GMPRootDir)/build-$(NativeToken)/gmp.h :
	rm -rf $(GMPDir) && mkdir -p $(GMPDir) && cd $(GMPDir) && ../configure $(LibsConfigFlags)

$(SGXOpenSSLLib) : $(OSSLDir)/sgxssl.1.9.100.99999.tar.gz
	cd $(OSSLDir) && tar xzf $<

$(OSSLDir)/sgxssl.1.9.100.99999.tar.gz : $(OSSLDir)/openssl_source/openssl-1.1.0g.tar.gz
	cd $(OSSLDir) && ./build_sgxssl.sh

$(OSSLDir)/openssl_source/openssl-1.1.0g.tar.gz :
	cd $(OSSLDir)/openssl_source/ && wget https://www.openssl.org/source/openssl-1.1.0g.tar.gz

################################################################################

$(BinDir):
	@mkdir $(BinDir)

$(ObjDir):
	@mkdir $(ObjDir)

.PHONY: clean clean-libs clean-all list

clean:
	rm -rf $(BinDir) $(ObjDir) $(SrcDir)/*_{t,u}.{c,h} 

clean-libs:
	rm -rf $(PBCDir) $(GMPDir)

clean-all: clean clean-libs

list:
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | xargs

