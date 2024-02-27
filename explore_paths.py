#!/usr/bin/env python3

from angr import Project, SimState, options as angroptions
from claripy import BVS
from claripy.ast.bv import BV

from collections.abc import Callable, Sequence
from typing import Tuple


# Solve for a concrete value that statisies the constraints over a given
# bitvector. This helper also silences a mistaken typing error from mypy.
def solve_for_symbolic_variable(state: SimState, bitvector: BV) -> bytes:
    return state.solver.eval(bitvector, cast_to=bytes)  # type: ignore


# Returns concrete arguments that drive the program to the given state.
def get_args_at_state(state: SimState,
                      args: Sequence[BV]) -> Sequence[Tuple[str, bytes]]:
    return [(arg._encoded_name.decode('UTF-8'),
             solve_for_symbolic_variable(state, arg))
            for arg in args]


Inputs = Sequence[Tuple[SimState, Sequence[Tuple[str, bytes]]]]


def get_inputs_for_paths(program: str,
                         num_args: int,
                         bytes_per_arg: int) -> Inputs:
    project = Project(program)

    # Get the entry point of the program and start the analysis there.
    # NOTE: It is also possible to start symbolic execution at an *arbitrary*
    # location inside a binary. This can be used both for focusing the
    # analysis and for improving overall scalability.
    #
    # In this case we want the command line arguments to be symbolic, and we
    # want symbolic arguments, so we specify them here. These arguments are
    # represented as symbolic bitvectors. The number of bits for each argument
    # is also specified.
    symbolic_args = [BVS('arg{}'.format(arg_num + 1), 8*bytes_per_arg)
                     for arg_num in range(num_args)]
    args = [program] + symbolic_args
    state = project.factory.entry_state(args=args)
    state.options.add(angroptions.SYMBOL_FILL_UNCONSTRAINED_MEMORY)

    # The simulation manager provides an interface to control the symbolic
    # execution decisions and how we explore, prioritize, merge, and split
    # the paths during the process. Here we simply run all paths to
    # completion. Clearly this will not always be possible.
    sm = project.factory.simulation_manager(state)
    sm.run()

    # Then we can extract the inputs associated with each individual path.
    state_inputs = [(state, get_args_at_state(state, symbolic_args))
                    for state in sm.deadended]
    return state_inputs


def dump_found_inputs(state_inputs: Inputs) -> None:
    print('Found {} paths'.format(len(state_inputs)))
    print('Proceeding to print outputs.\n')
    for i, (state, inputs) in enumerate(state_inputs):
        print('STATE: {}'.format(i))
        can_sat = state.satisfiable()
        print('FEASIBLE: {}'.format(can_sat))
        if not can_sat:
            continue

        # The 1 here corresponds to the standard posix file descriptor.
        # Here it is stdout.
        print('OUTPUT: {}'.format(state.posix.dumps(1)))
        for name, value in inputs:
            print('ARG Name:{} Value:{!r}'.format(name, value))
        print()


def main() -> None:
    PROGRAM = 'bin/simplepaths'
    NUM_ARGS = 3
    NUM_BYTES = 2
    STDOUT = 1

    state_inputs = get_inputs_for_paths(PROGRAM, NUM_ARGS, NUM_BYTES)
    dump_found_inputs(state_inputs)


if __name__ == '__main__':
    main()
