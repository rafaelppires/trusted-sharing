CC             := gcc
CXX            := g++-5
SHELL          := /bin/bash
SGX            := 0

SrcDir         := src
SGX_COMMONDIR  := $(realpath ../../sgx_common)
PBCRootDir     := $(realpath ../pbc-0.5.14)
GMPRootDir     := $(realpath ../gmp-6.1.2)

SgxToken       := sgx
NativeToken    := ntv

CFlags         := -m64
CPPFlags       := -std=c++11
CURVES_ENCLAVE := curves
TARGET         := $(CURVES_ENCLAVE)
Untrusted_Objs := $(TARGET).o
ENCLAVENAME    := enclave_$(TARGET)
ExternalLibs   := pbc gmp 

ifeq ($(SGX),1)
BuildToken  := $(SgxToken)
else
BuildToken  := $(NativeToken)
endif

GMPDir          := $(GMPRootDir)/build-$(BuildToken)
PBCDir          := $(PBCRootDir)/build-$(BuildToken)
GMPLib          := $(GMPDir)/.libs/libgmp.a
PBCLib          := $(PBCDir)/.libs/libpbc.a
ExtLibs         := $(PBCLib) $(GMPLib)
LibsConfigFlags := --with-pic=yes --enable-shared=no

BinDir  := bin-$(BuildToken)
ObjDir  := obj-$(BuildToken)

ifeq ($(SGX),1)
TRUSTEDOBJS          := $(ENCLAVENAME)_t.o ecalls_curves.o \
                        libc_proxy_t.o file_mock_t.o sdk_deprecated_t.o
SGX_SDK              := /opt/intel/sgxsdk
SGX_LIBRARY_PATH     := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER   := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R          := $(SGX_SDK)/bin/x64/sgx_edger8r
Trts_Library_Name    := sgx_trts
Service_Library_Name := sgx_tservice
App_Lib_Dirs         := $(SGX_LIBRARY_PATH) 
App_Libs             := sgx_uae_service sgx_urts 
CFlags               += -DENABLE_SGX
IncludeDirs          += $(SGX_SDK)/include
Untrusted_Objs       += ocalls.o
Untrusted_Objs       := $(filter-out $(TRUSTEDOBJS), $(Untrusted_Objs)) \
	                    $(ENCLAVENAME)_u.o
SGXCOMOBJS := $(addprefix $(ObjDir)/, sgx_initenclave.o sgx_errlist.o)
Enclave_Lib_Dirs     := $(SGX_LIBRARY_PATH) $(dir $(ExtLibs))
Enclave_Libs         := 
Enclave_SDK_Libs     := -Wl,--whole-archive \
                            -l$(Trts_Library_Name) \
                        -Wl,--no-whole-archive \
                        -Wl,--start-group \
                             $(addprefix -l, sgx_tstdc sgx_tstdcxx sgx_tcrypto \
                                             $(Service_Library_Name) ) \
                        -Wl,--end-group
Enclave_Link_Flags   := $(addprefix -L, $(Enclave_Lib_Dirs)) \
                        $(addprefix -l, $(Enclave_Libs)) \
                        $(Enclave_SDK_Libs)
Trusted_Link_Flags := -Wl,--no-undefined -nostdlib \
	-nodefaultlibs -nostartfiles $(Enclave_Link_Flags)  \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=$(SrcDir)/$(ENCLAVENAME).lds \
    $(addprefix -l, $(ExternalLibs) sgx_tstdc)
Common_C_Cpp_Flags := $(CFlags) -nostdinc -fvisibility=hidden \
	                  -fpie -fstack-protector -fno-builtin-printf
Enclave_C_Flags   := -Wno-implicit-function-declaration -std=c11 \
	                 $(Common_C_Cpp_Flags)
Enclave_Cpp_Flags := $(Common_C_Cpp_Flags) $(CPPFlags) -nostdinc++
Enclave_IncDirs   := $(SGX_SDK)/include/stlport $(SrcDir) $(SGX_SDK)/include \
                     $(SGX_SDK)/include/tlibc $(SGX_COMMONDIR) \
                     $(PBCRootDir)/include $(GMPDir)
Enclave_Include   := $(addprefix -I, $(Enclave_IncDirs))
App_Cpp_Objs      := $(SGXCOMOBJS)
Trusted_Objects   := $(addprefix $(ObjDir)/,$(TRUSTEDOBJS))
LibsConfigFlags   += --enable-sgx
all: $(BinDir)/$(TARGET) $(BinDir)/$(TARGET).signed.so
$(addprefix $(ObjDir)/,server_protocol.o $(TARGET).o): $(SrcDir)/$(ENCLAVENAME)_u.c
$(ObjDir)/query_manager.o : $(SrcDir)/$(ENCLAVENAME)_t.c
else
App_Lib_Dirs := $(dir $(ExtLibs))
App_Libs     := $(ExternalLibs)
LDFLAGS      := -static
all: $(BinDir)/$(TARGET)
endif

IncludeDirs    += $(SrcDir) $(SGX_COMMONDIR) $(PBCRootDir)/include/ $(GMPDir)/
App_Include    := $(addprefix -I, $(IncludeDirs))
App_Link_Flags := $(addprefix -L, $(App_Lib_Dirs)) \
                  $(addprefix -l, $(App_Libs))
App_Cpp_Objs   += $(addprefix $(ObjDir)/, $(Untrusted_Objs))


sgx_curves: $(CURVES_ENCLAVE) curves
$(ObjDir)/$(TARGET).o : $(GMPDir)/gmp.h

############## UNTRUSTED #######################################################
$(BinDir)/$(TARGET): ${App_Cpp_Objs} ${ExtLibs} | $(BinDir)
	@${CXX} $^ -o $@ ${App_Link_Flags} ${LDFLAGS}
	@echo -e "LINK (App)\t=>\t$@"

$(ObjDir)/%.o : $(SrcDir)/%.c | $(ObjDir)
	@${CC} ${CFlags} ${App_Include} -c $< -o $@
	@echo -e "CC (App)\t<=\t$<"

$(ObjDir)/%.o : $(SrcDir)/%.cpp | $(ObjDir)
	@${CXX} ${CPPFlags} ${CFlags} ${App_Include} -c $< -o $@
	@echo -e "CXX (App)\t<=\t$<"

$(SGXCOMOBJS) : $(ObjDir)/%.o : $(SGX_COMMONDIR)/%.cpp | $(ObjDir)
	@${CXX} ${CPPFlags} ${CFlags} ${App_Include} -c $< -o $@
	@echo -e "CXX (App)\t<=\t$<"

$(SrcDir)/$(ENCLAVENAME)_u.c : $(SrcDir)/$(ENCLAVENAME).edl $(SGX_EDGER8R)
	@cd $(dir $@) && $(SGX_EDGER8R) --untrusted ../$< --search-path ../$(dir $<) --search-path $(SGX_SDK)/include
	@echo -e "EDGER (App)\t=>\t$@"

############## TRUSTED #########################################################
$(BinDir)/$(TARGET).signed.so : %.signed.so : %.so
	@$(SGX_ENCLAVE_SIGNER) sign -enclave $< -config $(SrcDir)/$(ENCLAVENAME).config.xml -out $@ -key $(SrcDir)/enclave-key.pem
	@echo -e "SIGN (Enclave)\t=>\t$@"

$(BinDir)/$(TARGET).so : $(Trusted_Objects)
	$(CXX) $^ -o $@ $(Trusted_Link_Flags)
	@echo -e "LINK (Enclave)\t=>\t$@"

$(SrcDir)/$(ENCLAVENAME)_t.c : $(SrcDir)/$(ENCLAVENAME).edl $(SGX_EDGER8R)
	@cd $(dir $@) && $(SGX_EDGER8R) --trusted ../$< --search-path ../$(dir $<) --search-path $(SGX_SDK)/include
	@echo -e "EDGER (Enclave)\t=>\t$@"

$(ObjDir)/$(ENCLAVENAME)_t.o : $(SrcDir)/$(ENCLAVENAME)_t.c
	@${CC} -c $< -o $@ ${Enclave_C_Flags} ${Enclave_Include} 
	@echo -e "CC (Enclave)\t<=\t$<"

$(ObjDir)/%_t.o : $(SGX_COMMONDIR)/libc_mock/%.c
	@${CC} -c $< -o $@ ${Enclave_C_Flags} ${Enclave_Include} 
	@echo -e "CC (Enclave)\t<=\t$<"

$(ObjDir)/%_t.o : $(SGX_COMMONDIR)/libc_mock/%.cpp
	@${CXX} -c $< -o $@ ${Enclave_Include} ${Enclave_Cpp_Flags}
	@echo -e "CXX (Enclave)\t<=\t$<"

$(filter-out %_t.o, $(Trusted_Objects)) : $(ObjDir)/%.o : $(SrcDir)/%.cpp
	@${CXX} -c $< -o $@ ${Enclave_Include} ${Enclave_Cpp_Flags}
	@echo -e "CXX (Enclave)\t<=\t$<"
################################################################################
$(PBCLib) : $(GMPLib)
	rm -rf $(PBCDir) && mkdir -p $(PBCDir) && cd $(PBCDir) && LDFLAGS="-L$(GMPDir)/.libs" CPPFLAGS="-I$(PBCRootDir)/include -I$(GMPDir)" ../configure $(LibsConfigFlags) && make

$(GMPLib) : $(GMPDir)/gmp.h
	cd $(GMPDir) && make

$(GMPRootDir)/build-$(SgxToken)/gmp.h :
	rm -rf $(GMPDir) && mkdir -p $(GMPDir) && cd $(GMPDir) && ../configure $(LibsConfigFlags) && sed -i '39,42{s/^\/\///}' gmp.h

$(GMPRootDir)/build-$(NativeToken)/gmp.h :
	rm -rf $(GMPDir) && mkdir -p $(GMPDir) && cd $(GMPDir) && ../configure $(LibsConfigFlags)

################################################################################

$(BinDir):
	@mkdir $(BinDir)

$(ObjDir):
	@mkdir $(ObjDir)

.PHONY: clean clean-libs clean-all

clean:
	rm -rf $(BinDir) $(ObjDir) $(SrcDir)/*_{t,u}.{c,h} 

clean-libs:
	rm -rf $(PBCDir) $(GMPDir)

clean-all: clean clean-libs

