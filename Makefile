safeguards:
	g++ safeguards.cpp cryptography.cpp -o safeguards.out -l crypto -l pthread 	-I ../z3/src/api -I../z3/src/api/c++ -fopenmp -lrt -lz3

cryptography_for_ctypes:
	g++ -shared -o cryptography.so cryptography.cpp -l crypto -fPIC -D FOR_C

example:
	gcc z3_example.c -o z3_example.obj -c -I ../z3/src/api
	g++ z3_example.obj -l z3 -o z3_example.out

clean:
	rm -f *.obj *.out