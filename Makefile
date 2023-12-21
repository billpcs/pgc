linux:
		gcc -O2 pgc.c -o pgc

windows:
		gcc pgc.c -o pgc -lws2_32

clean:
		$(RM) pgc

test:
		cd tests && ./main.sh && cd ..
		cd tests && ./secondary.sh && cd ..

