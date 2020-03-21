linux:
		gcc -g pgc.c -o pgc

windows:
		gcc pgc.c -o pgc -lws2_32

clean:
		$(RM) pgc

test:
		cd tests && ./main.sh && cd ..

