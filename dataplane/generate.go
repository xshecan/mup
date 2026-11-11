package dataplane

//go:generate go tool bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I../bpf/include" mup ../bpf/mup.c
