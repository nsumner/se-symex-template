#!/usr/bin/env python3

import angr
import claripy


def get_args_at_state(state, args):
    return [(arg._encoded_name, state.solver.eval(arg, cast_to=bytes))
            for arg in args]


def get_inputs_for_paths(program, num_args, bytes_per_arg):
    project = angr.Project(program)
    
    # Get the entry point of the program and start the analysis there.
    # NOTE: It is also possible to start symbolic execution at an arbitrary
    # location inside a binary. This can be used both for focusing the
    # analysis and for improving overall scalability.
    #
    # In this case we want the command line arguments to be symbolic, and we
    # want symbolic arguments, so we specify them here. These arguments are
    # represented as symbolic bitvectors. The number of bits for each argument
    # is also specified.
    args = [program]
    args.extend(claripy.BVS('arg{}'.format(arg_num + 1), 8*num_args)
                for arg_num in range(num_args))
    state = project.factory.full_init_state(args=args)

    # The simulation manager provides an interface to control the symbolic
    # execution decisions and how we explore, prioritize, merge, and split
    # the paths during the process. Here we simply run all paths to
    # completion. Clearly this will not always be possible.
    sm = project.factory.simulation_manager(state)
    sm.run()

    # Then we can extract the inputs associated with each individual path.
    state_inputs = [(state, get_args_at_state(state, args[1:]))
                    for state in sm.deadended]
    return state_inputs


def dump_found_inputs(state_inputs):
    print('Found {} paths'.format(len(state_inputs)))
    print('Proceeding to print outputs.\n')
    for i, (state,inputs) in enumerate(state_inputs):
        print('STATE: {}'.format(i))
        can_sat = state.satisfiable()
        print('FEASIBLE: {}'.format(can_sat))
        if not can_sat:
            continue

        # The 1 here corresponds to the standard posix file descriptor.
        # Here it is stdout.
        print('OUTPUT: {}'.format(state.posix.dumps(1)))
        for name, value in inputs:
            print('ARG Name:{} Value:{}'.format(name, value))
        print()


if __name__ == '__main__':
    PROGRAM = 'bin/simplepaths'
    NUM_ARGS = 3
    NUM_BYTES = 2
    STDOUT = 1

    state_inputs = get_inputs_for_paths(PROGRAM, NUM_ARGS, NUM_BYTES)
    dump_found_inputs(state_inputs)
   

