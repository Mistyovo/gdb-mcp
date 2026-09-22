"""Task family registry."""

from __future__ import annotations

from . import breakpoints, crash, lifecycle, multistep, optimize, pie, threads

FAMILY_MODULES = {
    breakpoints.FAMILY: breakpoints,
    crash.FAMILY: crash,
    lifecycle.FAMILY: lifecycle,
    multistep.FAMILY: multistep,
    optimize.FAMILY: optimize,
    pie.FAMILY: pie,
    threads.FAMILY: threads,
}


def generate_family(name: str, seed: int):
    return FAMILY_MODULES[name].generate(seed)


def reference_solve_for(name: str):
    module = FAMILY_MODULES[name]
    return module.reference_solve
