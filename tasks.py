"""Tasks for use with Invoke."""

import os
import sys
from invoke import task

try:
    import toml
except ImportError:
    sys.exit(
        "Please make sure to `pip install toml` or enable the Poetry shell and run `poetry install`."
    )

# TODO: fix tasks.py to use poetry for running tests
# add task for ruff and better usage in general
PYPROJECT_CONFIG = toml.load("pyproject.toml")
TOOL_CONFIG = PYPROJECT_CONFIG["tool"]["poetry"]
# Can be set to a separate Python version to be used for launching or building image
PYTHON_VER = os.getenv("PYTHON_VER", "3.9")


def run_cmd(context, exec_cmd):
    """Wrapper to run the invoke task commands.

    Args:
        context ([invoke.task]): Invoke task object.
        exec_cmd ([str]): Command to run.
        local (bool): Define as `True` to execute locally

    Returns:
        result (obj): Contains Invoke result from running task.
    """
    result = context.run(exec_cmd, pty=True)
    return result


@task()
def black(context):
    """Run black to check that Python files adherence to black standards."""
    exec_cmd = "black --check --diff ."
    run_cmd(context, exec_cmd)


@task()
def flake8(context):
    """Run flake8 code analysis."""
    exec_cmd = "flake8 . --config .flake8"
    run_cmd(context, exec_cmd)


@task()
def pylint(context):
    """Run pylint code analysis."""
    exec_cmd = 'find . -name "*.py" | xargs pylint'
    run_cmd(context, exec_cmd)


@task()
def yamllint(context):
    """Run yamllint to validate formatting adheres to NTC defined YAML standards."""
    exec_cmd = "yamllint ."
    run_cmd(context, exec_cmd)


@task()
def bandit(context):
    """Run bandit to validate basic static code security analysis."""
    exec_cmd = "bandit --recursive ./ --configfile .bandit.yml"
    run_cmd(context, exec_cmd)


@task()
def tests(context):
    """Run all tests for this repository."""
    black(context)
    flake8(context)
    pylint(context)
    yamllint(context)
    bandit(context)
    # pytest(context)

    print("All tests have passed!")
