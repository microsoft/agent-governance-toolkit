// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// cspell:ignore talosrobotics
// Parser and shell-comment handling adapted from AGT PRs #4129 and #4142
// by Ricky-G (MIT). Earlier Claude Code rule fix: PR #3834 by talosrobotics.
// This is a bounded shell tokenizer, not a shell evaluator. Keep both packaged
// copies in sync; neither package can import runtime files from its sibling.
// A substitution contributes an unknown fragment to its enclosing shell word.
// NUL cannot occur in a shell argument; it keeps dynamic names/options opaque.
const DYNAMIC_WORD_FRAGMENT = "\0";

const SAFE_CLEANUP_TARGETS = new Set([
  "node_modules", "dist", "build", ".next", "target", "__pycache__",
  ".pytest_cache", ".venv", "venv", "coverage", ".turbo", "out",
]);

export function matchesRecursiveDeleteCommand(commandText) {
  const { commands } = tokenizeShellCommands(commandText);
  return commands.some((tokens) => {
    const invocation = getShellCommandInvocation(tokens);
    if (invocation?.name !== "rm") {
      return false;
    }

    let recursive = false;
    let force = false;
    let optionsEnded = false;
    for (const token of invocation.args) {
      if (optionsEnded) {
        continue;
      }
      if (token === "--") {
        optionsEnded = true;
        continue;
      }

      const option = parseRmOption(token);
      if (option) {
        recursive ||= option.recursive;
        force ||= option.force;
      }
    }

    return recursive && force;
  });
}

export function isSafeShellCleanupCommand(commandText) {
  const parsedCommand = tokenizeShellCommands(commandText);
  if (
    parsedCommand.hasControlOperator ||
    parsedCommand.hasUnterminatedSyntax ||
    parsedCommand.hasRedirection ||
    parsedCommand.commands.length !== 1
  ) {
    return false;
  }

  const invocation = getShellCommandInvocation(parsedCommand.commands[0]);
  if (invocation?.name !== "rm") {
    return false;
  }

  const candidateTargets = [];
  let optionsEnded = false;
  for (const token of invocation.args) {
    if (!token) {
      return false;
    }
    if (optionsEnded) {
      if (!addSafeCleanupTargets(candidateTargets, token)) {
        return false;
      }
      continue;
    }
    if (token === "--") {
      optionsEnded = true;
      continue;
    }
    if (token.startsWith("-")) {
      const option = parseRmOption(token);
      if (!option?.recognized) {
        return false;
      }
      continue;
    }
    if (!addSafeCleanupTargets(candidateTargets, token)) {
      return false;
    }
  }

  return candidateTargets.length > 0 && candidateTargets.every(isSafeCleanupTarget);
}

function getShellCommandInvocation(tokens) {
  let index = 0;
  while (index < tokens.length) {
    const token = tokens[index];
    // Assignment values may be dynamic; an executable name may not be inferred.
    if (token.includes(DYNAMIC_WORD_FRAGMENT) && !/^[a-z_][a-z0-9_]*=/i.test(token)) {
      return undefined;
    }
    const commandName = getLastPathSegment(token.replace(/\\/g, "/")).toLowerCase();
    if (
      ["if", "then", "do", "else", "elif", "while", "until", "in"].includes(commandName) ||
      /^[a-z_][a-z0-9_]*=/i.test(token)
    ) {
      index += 1;
      continue;
    }

    if (commandName === "exec") {
      index += 1;
      while (tokens[index]?.startsWith("-")) {
        const option = tokens[index];
        index += option === "-a" ? 2 : 1;
      }
      continue;
    }

    if (["command", "nohup", "busybox"].includes(commandName)) {
      index += 1;
      while (tokens[index]?.startsWith("-")) {
        const option = tokens[index++];
        if (option === "--") {
          break;
        }
        // Lookup/help modes do not execute the following command.
        if (
          (commandName === "command" && /^-[^-]*[vV]/.test(option)) ||
          ["--help", "--version", "--list", "--list-full"].includes(option)
        ) {
          return undefined;
        }
      }
      continue;
    }

    if (["nice", "time", "timeout"].includes(commandName)) {
      index += 1;
      const optionsWithArguments = {
        nice: new Set(["-n", "--adjustment"]),
        time: new Set(["-f", "--format", "-o", "--output"]),
        timeout: new Set(["-k", "--kill-after", "-s", "--signal"]),
      }[commandName];
      while (tokens[index]?.startsWith("-")) {
        const option = tokens[index];
        index += 1;
        if (option === "--") {
          break;
        }
        if (optionsWithArguments.has(option)) {
          index += 1;
        }
      }
      if (commandName === "timeout" && index < tokens.length) {
        index += 1;
      }
      continue;
    }

    if (commandName === "env") {
      index += 1;
      while (index < tokens.length) {
        const argument = tokens[index];
        if (["--help", "--version"].includes(argument)) {
          return undefined;
        }
        if (argument === "--") {
          index += 1;
          break;
        }
        if (["-u", "--unset", "-C", "--chdir"].includes(argument)) {
          index += 2;
        } else if (argument.startsWith("-") || /^[a-z_][a-z0-9_]*=/i.test(argument)) {
          index += 1;
        } else {
          break;
        }
      }
      continue;
    }

    if (commandName === "sudo" || commandName === "doas") {
      index += 1;
      while (index < tokens.length && tokens[index].startsWith("-")) {
        const option = tokens[index];
        index += 1;
        if (option === "--") {
          break;
        }
        const parsedOption = parseSudoWrapperOption(option);
        if (commandName === "sudo" && parsedOption.nonExecuting) {
          return undefined;
        }
        if (parsedOption.takesArgument) {
          index += 1;
        }
      }
      continue;
    }

    return {
      args: tokens.slice(index + 1),
      name: commandName,
    };
  }
  return undefined;
}

function parseSudoWrapperOption(option) {
  if (option.startsWith("--")) {
    const name = option.split("=")[0];
    return {
      nonExecuting: ["--list", "--version", "--help"].includes(name),
      takesArgument: !option.includes("=") && [
        "--user", "--group", "--host", "--prompt", "--close-from",
        "--chdir", "--chroot", "--command-timeout", "--role", "--type",
      ].includes(name),
    };
  }
  for (const [index, letter] of [...option.slice(1)].entries()) {
    if ("lV".includes(letter)) {
      return { nonExecuting: true, takesArgument: false };
    }
    // cspell:ignore ughp
    if ("ughpCDRTrt".includes(letter)) {
      // Any remaining characters belong to the argument, not to more flags.
      return { nonExecuting: false, takesArgument: index === option.length - 2 };
    }
  }
  return { nonExecuting: false, takesArgument: false };
}

function parseRmOption(token) {
  if (token.includes(DYNAMIC_WORD_FRAGMENT) || token === "-" || !token.startsWith("-")) {
    return undefined;
  }

  if (token.startsWith("--")) {
    const optionName = token.slice(2).split("=")[0].toLowerCase();
    if (optionName.startsWith("r") && "recursive".startsWith(optionName)) {
      return { force: false, recognized: true, recursive: true };
    }
    if (optionName.startsWith("f") && "force".startsWith(optionName)) {
      return { force: true, recognized: true, recursive: false };
    }

    return {
      force: false,
      recognized: [
        "dir",
        "help",
        "interactive",
        "no-preserve-root",
        "one-file-system",
        "preserve-root",
        "verbose",
        "version",
      ].includes(optionName),
      recursive: false,
    };
  }

  const optionLetters = token.slice(1).toLowerCase();
  return {
    force: optionLetters.includes("f"),
    // cspell:ignore firdv
    recognized: [...optionLetters].every((letter) => "firdv".includes(letter)),
    recursive: optionLetters.includes("r"),
  };
}

function addSafeCleanupTargets(candidateTargets, token) {
  // Never discard an uncertain target: doing so can exempt a mixed-target delete.
  // Commas are literal filename characters in a POSIX shell, not list separators.
  const cleaned = token.replace(/\/+$/, "");
  if (!cleaned || cleaned.includes(DYNAMIC_WORD_FRAGMENT) || /[\\*?\[\]{}$<>`]/.test(cleaned)) {
    return false;
  }
  candidateTargets.push(cleaned);
  return true;
}

function tokenizeShellCommands(commandText) {
  const input = String(commandText);
  const commands = [];
  let command = [];
  let token = "";
  let tokenStarted = false;
  let tokenWasQuoted = false;
  let quote;
  const substitutions = [];
  let hasControlOperator = false;
  let hasRedirection = false;
  let redirectionTargetPending = false;
  let backtickSubstitutionDepth = 0;

  const finishToken = () => {
    if (tokenStarted) {
      if (redirectionTargetPending) {
        redirectionTargetPending = false;
      } else {
        command.push(token);
      }
      token = "";
      tokenStarted = false;
      tokenWasQuoted = false;
    }
  };
  const finishCommand = () => {
    finishToken();
    if (command.length > 0) {
      commands.push(command);
      command = [];
    }
  };

  const startSubstitution = (frame) => {
    // Keep references to the enclosing state: copying at every nesting level
    // would make deep substitutions quadratic. Inner commands are scanned on
    // their own, then the outer word resumes with an opaque dynamic fragment.
    frame.enclosing = { command, token, tokenStarted, tokenWasQuoted, quote, redirectionTargetPending };
    substitutions.push(frame);
    command = [];
    token = "";
    tokenStarted = false;
    tokenWasQuoted = false;
    quote = undefined;
    redirectionTargetPending = false;
  };
  const finishSubstitution = () => {
    finishCommand();
    const frame = substitutions.pop();
    ({ command, token, tokenStarted, tokenWasQuoted, quote, redirectionTargetPending } = frame.enclosing);
    token += DYNAMIC_WORD_FRAGMENT;
    tokenStarted = true;
    tokenWasQuoted = true;
    if (frame.type === "backtick") backtickSubstitutionDepth -= 1;
  };

  for (let index = 0; index < input.length; index += 1) {
    const character = input[index];
    if (quote) {
      if (quote === '"' && character === "`") {
        hasControlOperator = true;
        startSubstitution({ type: "backtick" });
        backtickSubstitutionDepth += 1;
        continue;
      }
      if (quote === '"' && character === "$" && input[index + 1] === "(") {
        hasControlOperator = true;
        startSubstitution({
          depth: 1,
          type: "command",
        });
        index += 1;
        continue;
      }
      if (character === quote) {
        quote = undefined;
      } else if (quote === '"' && character === "\\" && index + 1 < input.length) {
        const nextCharacter = input[index + 1];
        if (['"', "\\", "$", "`"].includes(nextCharacter)) {
          token += nextCharacter;
          index += 1;
        } else if (nextCharacter !== "\n" && nextCharacter !== "\r") {
          token += character;
        }
      } else {
        token += character;
      }
      tokenStarted = true;
      continue;
    }

    const activeSubstitution = substitutions.at(-1);
    if (character === "`" && activeSubstitution?.type === "backtick") {
      hasControlOperator = true;
      finishSubstitution();
      continue;
    }
    if (character === "`") {
      hasControlOperator = true;
      startSubstitution({ type: "backtick" });
      backtickSubstitutionDepth += 1;
      continue;
    }
    if (["<", ">"].includes(character) && input[index + 1] === "(") {
      hasControlOperator = true;
      startSubstitution({ depth: 1, type: "command" });
      index += 1;
      continue;
    }
    if (character === "$" && input[index + 1] === "(") {
      hasControlOperator = true;
      startSubstitution({
        depth: 1,
        type: "command",
      });
      index += 1;
      continue;
    }
    if (activeSubstitution?.type === "command" && character === "(") {
      hasControlOperator = true;
      finishCommand();
      activeSubstitution.depth += 1;
      continue;
    }
    if (activeSubstitution?.type === "command" && character === ")") {
      hasControlOperator = true;
      activeSubstitution.depth -= 1;
      if (activeSubstitution.depth === 0) finishSubstitution();
      else finishCommand();
      continue;
    }

    const hashFollowsExpansionSyntax = ["{", "}", ")", "`"].includes(input[index - 1]);
    if (character === "#" && !tokenStarted && !hashFollowsExpansionSyntax) {
      const insideBacktickSubstitution = backtickSubstitutionDepth > 0;
      let precedingBackslashes = 0;
      while (index + 1 < input.length) {
        const nextCharacter = input[index + 1];
        if (
          nextCharacter === "\n" ||
          nextCharacter === "\r" ||
          (insideBacktickSubstitution &&
            nextCharacter === "`" &&
            precedingBackslashes % 2 === 0)
        ) {
          break;
        }
        precedingBackslashes = nextCharacter === "\\" ? precedingBackslashes + 1 : 0;
        index += 1;
      }
      finishCommand();
      if (input[index + 1] === "\r" && input[index + 2] === "\n") {
        hasControlOperator = true;
        index += 2;
      } else if (input[index + 1] === "\n" || input[index + 1] === "\r") {
        hasControlOperator = true;
        index += 1;
      }
      continue;
    }

    if (character === "'" || character === '"') {
      quote = character;
      tokenStarted = true;
      tokenWasQuoted = true;
      continue;
    }
    if (character === "\\") {
      const nextCharacter = input[index + 1];
      if (nextCharacter === "\n") {
        index += 1;
        continue;
      }
      if (nextCharacter === "\r" && input[index + 2] === "\n") {
        index += 2;
        continue;
      }
      if (nextCharacter !== undefined) {
        token += nextCharacter;
        tokenStarted = true;
        tokenWasQuoted = true;
        index += 1;
      } else {
        token += character;
        tokenStarted = true;
      }
      continue;
    }
    if (/[ \t\r\n]/.test(character)) {
      finishToken();
      if (character === "\n" || character === "\r") {
        hasControlOperator = true;
        finishCommand();
        if (character === "\r" && input[index + 1] === "\n") {
          index += 1;
        }
      }
      continue;
    }
    if (
      character === ">" || character === "<" ||
      (character === "&" && input[index + 1] === ">")
    ) {
      // Redirection syntax and its operand are not rm arguments. Quoted or
      // escaped operators never enter this branch and remain literal words.
      hasRedirection = true;
      if (!tokenWasQuoted && /^\d+$/.test(token)) {
        token = "";
        tokenStarted = false;
      } else {
        finishToken();
      }
      let operator = character;
      if (character === "&") {
        operator += input[++index];
      }
      if (input[index + 1] === ">" && operator.endsWith(">")) {
        index += 1;
      } else if (input[index + 1] === "<" && character === "<") {
        index += 1;
        if (input[index + 1] === "<") index += 1;
        else if (input[index + 1] === "-") index += 1;
      } else if (
        ["&", "|"].includes(input[index + 1]) ||
        (character === "<" && input[index + 1] === ">")
      ) {
        index += 1;
      }
      redirectionTargetPending = true;
      continue;
    }
    if (";|&(){} `".includes(character)) {
      hasControlOperator = true;
      finishCommand();
      if (
        (character === "|" || character === "&") &&
        input[index + 1] === character
      ) {
        index += 1;
      }
      continue;
    }

    token += character;
    tokenStarted = true;
  }
  const hasUnterminatedSyntax = Boolean(quote || substitutions.length || redirectionTargetPending);
  // Keep static outer flags visible even if an inner substitution never closes.
  // The malformed-syntax flag still prohibits the cleanup exception.
  while (substitutions.length > 0) finishSubstitution();
  finishCommand();
  return { commands, hasControlOperator, hasRedirection, hasUnterminatedSyntax };
}

function isSafeCleanupTarget(target) {
  if (
    !target ||
    target.startsWith("/") ||
    /^[a-z]:/i.test(target) ||
    target.includes("..") ||
    target.includes("~")
  ) {
    return false;
  }

  const normalized = target.replace(/^\.\//, "");
  return SAFE_CLEANUP_TARGETS.has(getLastPathSegment(normalized));
}

function getLastPathSegment(value) {
  return String(value).split("/").filter(Boolean).at(-1) ?? "";
}
