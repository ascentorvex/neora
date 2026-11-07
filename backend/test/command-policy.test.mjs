import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateCommand } from '../tools.mjs';

test('allows quoted restricted Python code', () => {
  assert.equal(evaluateCommand('python3 -c "print(1 + 1)"').allowed, true);
  assert.equal(evaluateCommand('python3 -c "x = [1, 2, 3]; print(sum(x))"').allowed, true);
  assert.equal(evaluateCommand("python3 -c 'print(\"hello\")'").allowed, true);
});

test('denies shell commands and shell suffixes', () => {
  for (const cmd of ['echo hi; id', 'cat /etc/passwd', 'echo $(id)', 'python3 -c "print(1)" > /tmp/a']) {
    assert.equal(evaluateCommand(cmd).allowed, false, cmd);
  }
});

test('denies unquoted or empty code and non-Python binaries', () => {
  for (const cmd of ['python3 -c print(1)', 'curl https://example.com', 'sh -c "id"', 'python3 -c ""']) {
    assert.equal(evaluateCommand(cmd).allowed, false, cmd);
  }
});
