"""BashCommandHook must not let interpolated (untrusted) values inject shell commands.

Finding: execute() interpolated context values (incl. agent-controlled tool_input)
into a string run under subprocess.run(shell=True) with no escaping, so a value
containing shell metacharacters (;, |, $(), `, &&) executed arbitrary commands on
the host.
"""

from __future__ import annotations

from pi_agent_chain.governance.hooks import BashCommandHook


def test_bash_hook_does_not_execute_injected_commands():
    hook = BashCommandHook(command="echo {tool_input.message}")
    out = hook.execute({"tool_input": {"message": "x; echo OWNED"}})
    assert out["exit_code"] == 0
    # The whole value must be echoed LITERALLY as one argument — not run as a
    # second command (which would print 'x' then 'OWNED' on separate lines).
    assert out["stdout"].strip() == "x; echo OWNED"


def test_bash_hook_blocks_command_substitution():
    hook = BashCommandHook(command="echo {tool_input.message}")
    out = hook.execute({"tool_input": {"message": "$(echo PWNED)"}})
    assert out["stdout"].strip() == "$(echo PWNED)"  # not expanded/executed


def test_bash_hook_normal_value_still_works():
    hook = BashCommandHook(command="echo {tool_input.message}")
    out = hook.execute({"tool_input": {"message": "hello world"}})
    assert out["stdout"].strip() == "hello world"
