.PHONY: all build test install reinstall uninstall clean

NAME=dnscurve
VERSION=0.0.1
PKGS=sodium,cstruct,dns
OBJS=base32
TESTS=test
TESTT=native

CMIS=$(addprefix lib/,$(addsuffix .cmi,${OBJS}))
CMOS=$(addprefix lib/,$(addsuffix .cmo,${OBJS}))
CMXS=$(addprefix lib/,$(addsuffix .cmx,${OBJS}))
CMA=lib/${NAME}.cma
CMXA=lib/${NAME}.cmxa
A=lib/${NAME}.a
B=_build/lib/
INSTALL=META $(addprefix _build/,${CMA} ${CMXA} ${A} ${CMIS})

FLAGS=-use-ocamlfind -tag thread

build: ${CMA} ${CMXA} ${A}

all: build test install

test: build $(addprefix lib_test/,$(addsuffix .${TESTT},${TESTS}))

lib_test/%.${TESTT}: lib_test/%.ml
	ocamlbuild ${FLAGS} -pkgs ${PKGS},oUnit -I lib $@
	${MAKE} -C lib_test
	./$*.${TESTT}

%.cmo: %.ml %.mli
	ocamlbuild ${FLAGS} -pkgs ${PKGS} $@

%.cma: ${CMOS}
	ocamlbuild ${FLAGS} -lflag -thread -pkgs ${PKGS} $@

%.cmx: %.ml %.mli
	ocamlbuild ${FLAGS} -pkgs ${PKGS} $@

%.cmxa: ${CMXS}
	ocamlbuild ${FLAGS} -lflag -thread -pkgs ${PKGS} $@

%.a: ${CMXS}
	ocamlbuild ${FLAGS} -lflag -thread -pkgs ${PKGS} $@

META: META.in
	sed s/%%VERSION%%/${VERSION}/ < META.in \
	| sed s/%%PACKAGES%%/${PKGS}/ > META

install: build ${INSTALL}
	ocamlfind install ${NAME} ${INSTALL}

reinstall: uninstall install

uninstall:
	ocamlfind remove ${NAME}

clean:
	${MAKE} -C lib_test clean
	rm -rf _build META $(addsuffix .${TESTT},${TESTS})
