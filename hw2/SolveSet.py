# Name: Sean-Wyn Ng
# Description: Solves set game combinations. Received help from Kexin Jin on the syntax for comparing Xij elements directly.
# Received help from Emily Yin debugging valid set constraints (range and logical operator were missing)
#
from SetGame import *
from z3 import *
from itertools import permutations

def matrixVar(i, p):
	"""
	Create a variable representing a single property of a card (number, color, shape, or pattern)
	These are the cells of the matrix
	"""
	return Int("x_%s_%s" % (i,p))

def getSetMatrix():
	"""Create a 3x4 matrix to represent a candidate set: 3 cards, 4 properties each"""
	return [ [ matrixVar(i+1, p+1) for p in range(4) ] 
			 for i in range(3) ]

def addValueConstraints(X):
	"""Add constraints such that each value is between 1 and 3"""
	constraints = []
	for i in range(3):
		for p in range(4):
			constraints.append(And(1 <= X[i][p], X[i][p] <= 3))

	return constraints

def addDuplicateConstraints(X):
	"""Add constraints to ensure that there are no duplicate cards in the set"""
	constraints = []

	# ---- Student code begin ---- #
	# iterate through the matrix provided
	cards = []

	# compare all cards
	for i in range(3):
		for k in range(i + 1, 3):
			constraints.append(Not(And([X[i][j] == X[k][j] for j in range(4)])))

	return constraints

def addBoardConstraints(X,board):
	"""Add constraints to ensure all cards in the set are on the board"""
	constraints = []
	cards_on_board = [c.asListforZ3() for c in board.getCardList()]

	# ---- Student code begin ---- #
	# iterate through the cards in set, check if they are on board

	cards = []

	# each card must be on the board
	for i in range(3):
		# X[i] only needs to match one of the cards
		constraints.append(Or([And([X[i][j] == card[j] for j in range(4)]) for card in cards_on_board]))
	# ---- Student code end ---- #

	return constraints

def addPrevFoundSetsConstraints(X,found_sets):
	"""Add constraint to ensure set hasn't already been found"""
	constraints = []

	# ---- Student code begin ---- #
	# each element in found_sets is a found set

	for set in found_sets:
		# make sure cards isn't in found_sets, already generated permutations
		
		# comparing my cards (X) to all three cards in the set
		constraints.append(Not(And([X[i][j] == set[i][j] for j in range(3) for i in range(2)])))

	# ---- Student code end ---- #
	
	return constraints

def addValidSetConstraints(X):
	"""
	Add constraints to make sure it's a valid set
	(for each property, all 3 cards are the same or all 3 are different)
	"""
	constraints = []
	
	# ---- Student code begin ---- #

	# iterate over each property
	for i in range(4):
		constraints.append(And([Or(And([(X[j][i] == X[k][i]) for j in range(3) for k in range(j + 1, 3)]), 
		And([(X[j][i] != X[k][i]) for j in range(3) for k in range(j + 1, 3)]))]))

	# ---- Student code end ---- #

	return constraints


def solveSet(board,found_sets,printErr=True):
	X = getSetMatrix()

	# Create the Z3 solver
	solver = Solver()

	# Convert found_sets to Z3 format and generate permutations
	Z3_found_sets = []
	for s in [[c.asListforZ3() for c in s] for s in found_sets]:
		for p in list(permutations(s)):
			Z3_found_sets.append(list(p))

	# Add all constraints
	solver.add(addValueConstraints(X))
	solver.add(addDuplicateConstraints(X))
	solver.add(addBoardConstraints(X,board))
	solver.add(addPrevFoundSetsConstraints(X,Z3_found_sets))
	solver.add(addValidSetConstraints(X))


	# If the problem is satisfiable, a solution exists
	if solver.check() == sat:
		m = solver.model()
		r = [ [ m.evaluate(X[i][j]).as_long() for j in range(4) ] 
			  for i in range(3) ]
		return r
	else:
		if printErr:
			print("Could not satisfy the constraints.")
		return None

##################################
