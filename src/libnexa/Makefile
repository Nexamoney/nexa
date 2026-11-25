# This is a standalone makefile the produces libnexalight.so/.a for light client wallets.
# This is a subset of the normal libnexa.so.  It includes the script machine, which needs libgmp.
# libgmp is built from source for the target (see buildGmp.sh; run downloadGmpLib.sh first) into ${BUILD_DIR}/gmp.
# libgmp is linked into libnexalight.so.  It is NOT merged into libnexalight.a: ${BUILD_DIR}/gmp/lib/libgmp.a must be
# linked alongside it.
# Pass NO_SCRIPT_MACHINE=1 to build without the script machine (and without libgmp).

# It expects BUILD_DIR, TARGET, CXX, CC, LD, AR, AS, RANLIB, STRIP variables to be set
# GMP_HOST may be set to the gmp configure --host triple when cross compiling
# and the object files will be built in the current directory

makefilePath := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
srcDir := $(abspath ${makefilePath}/..)

srcFilenames := $(shell cat nexalightcfiles.txt)
# $(warning ${srcFilenames})

# linuxX64
# srcFilenames += crypto/sha256_avx2.cpp crypto/sha256_sse41.cpp crypto/sha256_sse4.cpp

ifeq ($(NO_SCRIPT_MACHINE),1)
srcFilenames := $(filter-out libnexa/libnexa_script_machine.cpp,$(srcFilenames))
scriptMachineDefs := -DNO_SCRIPT_MACHINE
gmpLib :=
gmpIncludes :=
else
scriptMachineDefs :=
gmpPrefix := ${BUILD_DIR}/gmp
gmpLib := ${gmpPrefix}/lib/libgmp.a
gmpIncludes := -I${gmpPrefix}/include
endif

srcFilePath := $(addprefix $(srcDir)/, $(srcFilenames))

srcObjs := $(addprefix ${BUILD_DIR}/,$(addsuffix .o,$(basename $(notdir ${srcFilePath}))))
# $(warning ${srcObjs})

# NEXA_CONFIG_DIR: the per-platform directory holding nexa-config.h.  It must be first, so it wins over any stale
# nexa-config.h in the source tree.  Defaults to this directory, where nexa-config.h used to be copied.
NEXA_CONFIG_DIR ?= ${srcDir}/libnexa
cIncludes := -I${NEXA_CONFIG_DIR} -I${srcDir}/libnexa -I${srcDir} -I${srcDir}/script -I${srcDir}/config  -I${srcDir}/validation -I${srcDir}/secp256k1/include -I${srcDir}/secp256k1 -I${srcDir}/secp256k1/src -I${srcDir}/libnexa/boost ${gmpIncludes}
cxxflags := ${CXXFLAGS} -c -MMD -MP -DHAVE_CONFIG_H -DBOOST_SYSTEM_NO_DEPRECATED -DBOOST_MP_STANDALONE -D${PLATFORM} -DLIGHT -DBUILD_ONLY_LIBNEXA ${scriptMachineDefs} -fPIC -Wno-tautological-constant-compare -std=gnu++17 ${cIncludes}
cflags := ${CFLAGS} -c -MMD -MP -DHAVE_CONFIG_H -DBOOST_SYSTEM_NO_DEPRECATED -DBOOST_MP_STANDALONE -D${PLATFORM} -DLIGHT -DBUILD_ONLY_LIBNEXA ${scriptMachineDefs} -fPIC -Wno-tautological-constant-compare -DVERIFY ${cIncludes}


all: ${BUILD_DIR}/libnexalight.a ${BUILD_DIR}/libnexalight.so

# ARE YOU GETTING?: make[1]: *** No rule to make target 'file.o', needed by '/fast/nexa/lnk/libnexa/nexa/build_LINUX_host/lightbuild/libnexalight.so'.  Stop.
# You need to add the directory of your new file into the build rules below

${BUILD_DIR}/libnexalight.a: ${srcObjs}
	${AR} rvs $@ $^

# Every object depends on gmp.h (via script/bignum.h), so build libgmp before compiling anything
${srcObjs}: | ${gmpLib}

${BUILD_DIR}/gmp/lib/libgmp.a:
	./buildGmp.sh ${BUILD_DIR}/gmp

# why the flock? occasionally: lightbuild/sqlite3.o: file not recognized: file truncated
# BUT when you ls the file it is NOT truncated.  This is the last file to be built.  There appears to be a bug in make waiting before launching dependent tasks
# .o file is touched right away, so it exists, triggering this rule to run.  But it has not been fully written
${BUILD_DIR}/libnexalight.so: ${srcObjs} ${gmpLib}
	[ "$$(uname)" = "Darwin" ] && (sleep 3 && echo 'sleeping on macOS') || flock /tmp/compiled.lock -c 'echo sqlite file is ready'
	${CXX} -shared -o $@ $^

${BUILD_DIR}/%.o: %.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../script/%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../primitives/%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../crypto/%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../capd/%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../support/%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../consensus/%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../validation/%.cpp
	${CXX} ${cxxflags} -o $@ $<

${BUILD_DIR}/%.o: ../secp256k1/src/%.c
	${CC} ${cflags} -o $@ $<

${BUILD_DIR}/%.o: sqlite/%.c
	[ "$$(uname)" = "Darwin" ] && (${CC} ${cflags} -o $@ $<) || flock -x /tmp/compiled.lock -c '${CC} ${cflags} -o $@ $< && sync'

# Header dependencies, written by -MMD next to each object.  Without these, a changed header (for example bignum.h, whose
# BigNum class is a stub when NO_SCRIPT_MACHINE is defined) leaves stale objects built against the old class layout,
# and the library then crashes.
-include $(srcObjs:.o=.d)
