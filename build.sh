#!/bin/bash

ROOT_DIR=$(dirname $(realpath -s $0))

CC='clang'

# CFLAGS_DEBUG='-g'

CFLAGS_OPTIMIZE='-O2'
CFLAGS_STD='-std=c23'

CFLAGS_WARNINGS='-Wextra -Wall -Wpedantic -Wundef -Wshadow -Wpointer-arith -Wstrict-prototypes -Wunreachable-code -Wformat=2 -Wold-style-definition -Wredundant-decls -Wnested-externs -Wmissing-include-dirs'

LIB_SNAPPY_OBJ="${ROOT_DIR}/deps/snappy/build/libsnappy.a"
LIB_SNAPPY_INC="-I${ROOT_DIR}/deps/snappy"

PROTO_INC="-I${ROOT_DIR}/ -I${ROOT_DIR}/deps/protobuf-c/"
PROTO_ROOT_DIR="${ROOT_DIR}/protos"
PROTO_SRCS="${PROTO_ROOT_DIR}/demo.pb-c.c ${PROTO_ROOT_DIR}/gameevents.pb-c.c ${PROTO_ROOT_DIR}/networkbasetypes.pb-c.c ${PROTO_ROOT_DIR}/network_connection.pb-c.c ${PROTO_ROOT_DIR}/google/protobuf/descriptor.pb-c.c ${PROTO_ROOT_DIR}/netmessages.pb-c.c"

CFLAGS_LIBS="-lrt -lc -lprotobuf-c -lstdc++ ${LIB_SNAPPY_OBJ}"
CFLAGS="${CFLAGS_STD} ${CFLAGS_DEBUG} ${CFLAGS_OPTIMIZE} ${CFLAGS_WARNINGS}"
CFLAGS_INC="${LIB_SNAPPY_INC} ${PROTO_INC}"

SOURCE_FILES="main.c ${PROTO_SRCS}"
OUT_EXE_NAME='demo_parser'

time $CC $CFLAGS $CFLAGS_INC $SOURCE_FILES -o $OUT_EXE_NAME $CFLAGS_LIBS