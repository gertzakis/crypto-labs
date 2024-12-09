"""Tasks for use with Invoke."""

from invoke.exceptions import Exit
from invoke.tasks import task

# TODO: fix tasks.py to use poetry for running tests


def run_command(context, command, **kwargs):
    """Wrapper to run the invoke task commands.

    Args:
        context ([invoke.task]): Invoke task object.
        command (str): Command to run.
        **kwargs: Additional arguments to pass to the context.run method.

    Returns:
        result (obj): Contains Invoke result from running task.
    """
    result = context.run(command, **kwargs)
    return result


# ------------------------------------------------------------------------------
# BUILD
# ------------------------------------------------------------------------------
@task(
    help={
        "check": (
            "If enabled, check for outdated dependencies in the poetry.lock file, "
            "instead of generating a new one. (default: disabled)"
        )
    }
)
def lock(context, check=False):
    """Generate poetry.lock."""
    run_command(context, f"poetry {'check' if check else 'lock --no-update'}")


# ------------------------------------------------------------------
# TESTS
# ------------------------------------------------------------------------------


@task
def flake8(context):
    """Run flake8 code analysis."""
    exec_cmd = "flake8 . --config .flake8"
    run_command(context, exec_cmd)


@task
def pylint(context):
    """Run pylint code analysis."""
    command = 'find . -name "*.py" | xargs pylint --rcfile pyproject.toml'
    run_command(context, command)


@task
def yamllint(context):
    """Run yamllint to validate formatting adheres to NTC defined YAML standards.

    Args:
    ----
        context (obj): Used to run specific commands
    """
    command = "yamllint . --format standard"
    run_command(context, command)


@task
def bandit(context):
    """Run bandit to validate basic static code security analysis."""
    exec_cmd = "bandit --recursive ./ --configfile .bandit.yml"
    run_command(context, exec_cmd)


@task(
    help={
        "action": "Available values are `['lint', 'format']`. Can be used multiple times. (default: `['lint', 'format']`)",
        "target": "File or directory to inspect, repeatable (default: all files in the project will be inspected)",
        "fix": "Automatically fix selected actions. May not be able to fix all issues found. (default: False)",
        "output_format": "See https://docs.astral.sh/ruff/settings/#output-format for details. (default: `concise`)",
    },
    iterable=["action", "target"],
)
def ruff(context, action=None, target=None, fix=False, output_format="concise"):
    """Run ruff to perform code formatting and/or linting."""
    if not action:
        action = ["lint", "format"]
    if not target:
        target = ["."]

    exit_code = 0

    if "format" in action:
        command = "ruff format "
        if not fix:
            command += "--check "
        command += " ".join(target)
        if not run_command(context, command, warn=True):
            exit_code = 1

    if "lint" in action:
        command = "ruff check "
        if fix:
            command += "--fix "
        command += f"--output-format {output_format} "
        command += " ".join(target)
        if not run_command(context, command, warn=True):
            exit_code = 1

    raise Exit(code=exit_code)


@task(
    help={
        "test_case": "Specific test case to run (default: None)",
        "verbose": "Enable verbose output (default: False)",
    },
)
def unittest(context, test_case=None, verbose=False):
    """Run unit tests."""
    exec_cmd = "python3 -m unittest"
    if test_case:
        exec_cmd += f" {test_case}"
    if verbose:
        exec_cmd += " -v"
    run_command(context, exec_cmd)


@task()
def tests(context):
    """Run all tests for this repository."""
    flake8(context)
    pylint(context)
    yamllint(context)
    bandit(context)
    unittest(context)
    ruff(context)

    print("All tests have passed!")
