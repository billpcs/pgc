all: pgc test

pgc:
		gcc -g pgc.c -o pgc

clean:
		rm pgc

test:
		cd tests && ./main.sh && cd ..

