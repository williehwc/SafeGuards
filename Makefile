safeguards:
	gcc safeguards.c -o safeguards.out
	gcc msg_sender.c -o msg_sender.out

example:
	gcc z3_example.c -o z3_example.obj -c -I ../z3/src/api
	g++ z3_example.obj -l z3 -o z3_example.out

clean:
	rm -f *.obj *.out