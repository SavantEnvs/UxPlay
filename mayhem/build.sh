#!/usr/bin/env bash
#
# mayhem/build.sh — build UxPlay's libairplay (lib/, lib/llhttp, lib/playfair) sanitized and link the
# loopback-socket harnesses against it; also build the known-answer selftest with normal flags.
#
# Upstream's top-level CMakeLists.txt also configures the GStreamer frontend (uxplay.cpp, renderers/),
# which is not part of the parsed surface, so the library sources are compiled here directly with the
# definitions lib/CMakeLists.txt sets on Linux (STANDALONE, TARGET_POSIX, _LINUX, NOHOLD, PLIST_2x0,
# OPENSSL_API_COMPAT). All outputs land in build/ (gitignored upstream), so `git clean -ffdX` removes
# them and a re-run rebuilds from scratch.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

PKGS="libplist-2.0 openssl avahi-compat-libdns_sd"
DEFS="-DSTANDALONE -D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS -DTARGET_POSIX -D_LINUX -D_REENTRANT \
 -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DNOHOLD -DOPENSSL_API_COMPAT=0x10101000L"
pkg-config --atleast-version=2.1.0 libplist-2.0 && DEFS="$DEFS -DPLIST_210"
pkg-config --atleast-version=2.3.0 libplist-2.0 && DEFS="$DEFS -DPLIST_230"
INCS="-I$SRC/lib -I$SRC/lib/llhttp -I$SRC/lib/playfair $(pkg-config --cflags $PKGS)"
LIBS="$(pkg-config --libs $PKGS) -lpthread -lm"
LIB_SRCS=$(ls lib/*.c lib/llhttp/*.c lib/playfair/*.c)

# build_lib <outdir> <cflags...>: compile every library source into <outdir>/libairplay.a
build_lib() {
  local out="$1"; shift
  rm -rf "$out"; mkdir -p "$out/obj"
  printf '%s\n' $LIB_SRCS | xargs -P "$MAYHEM_JOBS" -I{} sh -c \
    'o="$0/obj/$(echo "{}" | tr / _).o"; '"$CC"' '"$*"' '"$DEFS"' '"$INCS"' -c "{}" -o "$o"' "$out"
  llvm-ar rcs "$out/libairplay.a" "$out"/obj/*.o
}

# 1) fuzz build: the whole library + harnesses with sanitizers and DWARF 3
F=build/mayhem-fuzz
# -fsanitize=fuzzer-no-link: SanCov on the library, whose code runs in the server thread
COV_FLAGS="-fsanitize=fuzzer-no-link"
# UBSan's alignment check is relaxed: byteutils.c reads big/little-endian fields straight out of
# packet buffers at odd offsets (every mirror codec packet), which is benign on x86/arm64 and would
# otherwise stop the mirror target on its first input. ASan and the rest of UBSan still halt.
COV_FLAGS="$COV_FLAGS -fno-sanitize=alignment"
build_lib "$F" -O1 $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$F/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$F/standalone_main.o"
for t in fuzz_raop_rtsp:"" fuzz_airplay_http:"-DFUZZ_HLS"; do
  name="${t%%:*}"; def="${t#*:}"
  $CC $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS $def $DEFS $INCS -c mayhem/harnesses/fuzz_raop.c -o "$F/$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$F/$name.o" "$F/lsan_off.o" \
      "$F/libairplay.a" $LIBS -o "$SRC/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$F/standalone_main.o" "$F/$name.o" "$F/lsan_off.o" \
      "$F/libairplay.a" $LIBS -o "$SRC/$name-standalone"
done
for name in fuzz_mirror fuzz_audio; do
  $CC $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS $DEFS $INCS -c "mayhem/harnesses/$name.c" -o "$F/$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$F/$name.o" "$F/lsan_off.o" \
      "$F/libairplay.a" $LIBS -o "$SRC/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$F/standalone_main.o" "$F/$name.o" "$F/lsan_off.o" \
      "$F/libairplay.a" $LIBS -o "$SRC/$name-standalone"
done

# 2) test build: same library with normal flags (no sanitizers) + the known-answer selftest
T=build/mayhem-test
build_lib "$T" -O2 $COVERAGE_FLAGS
$CC -O2 $COVERAGE_FLAGS $DEFS $INCS mayhem/harnesses/raop_selftest.c "$T/libairplay.a" $LIBS \
    $COVERAGE_FLAGS -o "$T/raop_selftest"
echo "build.sh: built $SRC/fuzz_raop_rtsp $SRC/fuzz_airplay_http $SRC/fuzz_mirror $SRC/fuzz_audio (+ -standalone) and $T/raop_selftest"
