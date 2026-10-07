<!-- surf-roadmap:block id=header v=1 -->
# Project conventions

This section is managed by the `surf-roadmap` plugin. Everything between a
`surf-roadmap:block` marker and its matching `surf-roadmap:end` marker comes from
one shared definition: `/surf-roadmap:setup` writes it and
`/surf-roadmap:check-project` audits it. Change the plugin, not these blocks.
Anything outside the markers is project-specific and is never read or rewritten.

**Precedence.** These rules override any global or user-level `CLAUDE.md`,
personal defaults and tool defaults for work in this repository. Where this file
is silent, other instructions apply.
<!-- surf-roadmap:end id=header -->

<!-- surf-roadmap:block id=roadmap v=1 -->
## Roadmap

This repository is linked to the roadmap project named in `surf-roadmap.json`.
Specs, implementation plans, ADRs and open questions live in the roadmap and are
read and written through the `surf-roadmap` MCP server. No agent writes them as
files: no `docs/specs`, `docs/plans`, `docs/adr`, `docs/superpowers`, `SPEC.md` or
similar.

Use the `surf-roadmap:*` skills. They replace the `superpowers:*` skills in this
repository, which are blocked. Keep the roadmap current while working: start a
task with `update_task` (state `doing`), `post_update` after every commit, and
mark tasks and systems done when finished.
<!-- surf-roadmap:end id=roadmap -->

<!-- surf-roadmap:block id=language v=1 -->
## Language

All output is **English**: code, identifiers, comments, doc comments, commit
messages, branch names, specs, plans, ADRs, questions, progress updates and the
agent's own replies in chat.

This holds whatever language the human writes in and whatever language existing
files use. If the human writes in German, the agent answers in English. The agent
does not ask whether to translate and does not mirror the human's language.
<!-- surf-roadmap:end id=language -->

<!-- surf-roadmap:block id=never-assume v=1 -->
## Never assume — ask

Agents do not get to decide. When a task is underspecified, when two reasonable
implementations exist, or when a name, format, dependency, trade-off or scope
boundary is open, the agent **asks the human, using the question tool, before
writing code**.

- A plausible default is not permission.
- "I picked the common option" is not an acceptable justification.
- If the agent catches itself about to write "I assumed", it stops and asks instead.
- Related questions are batched into one round rather than drip-fed one at a time.

The only decisions an agent may make alone are the ones with no lasting
consequence and no alternative worth naming.
<!-- surf-roadmap:end id=never-assume -->

<!-- surf-roadmap:block id=adr v=1 -->
## Decisions become ADRs

**Every decision that requires a human becomes an ADR in the roadmap.**

A decision requires a human when it:

- constrains future work,
- is expensive to reverse,
- trades one desirable property against another,
- affects the security model,
- changes a public API, a wire format or an on-disk format, or
- adds a runtime dependency.

Process: the agent identifies the decision, asks the human with the real options
and their real trade-offs, and only after the human decides records it with
`/surf-roadmap:new-adr` (`create_adr`, then `accept_adr` once the human confirms
the text). ADRs are numbered by the roadmap and **immutable once accepted**. A
changed decision is a new ADR; the old one is superseded with `supersede_adr`,
and its text is never edited.
<!-- surf-roadmap:end id=adr -->

<!-- surf-roadmap:block id=workflow v=1 -->
## Workflow: prompt -> interview -> spec -> plan -> execution

```
1. Prompt              The human states what they want.
2. Planning interview  /surf-roadmap:plan-system asks question rounds until every area
                       is covered and every risk is answered or explicitly accepted.
                       Every round is stored in the roadmap.
3. Spec                Written to the roadmap with write_spec and confirmed by the
                       human in their own words; complete_planning records it.
4. Plan                Only after planning is complete: /surf-roadmap:write-plan,
                       stored with write_plan; its steps become the system's tasks.
5. Execution           /surf-roadmap:execute-plan or
                       /surf-roadmap:subagent-driven-development, as the
                       execution-mode block of this file says.
```

- Step 2 is never skipped, even when the prompt looks complete.
- Implementation does not start before step 4. The roadmap server enforces this:
  systems cannot leave planning and tasks cannot start before planning is complete.
- If reality contradicts the plan, the agent stops and asks. It does not silently
  rewrite the plan to match what happened.
<!-- surf-roadmap:end id=workflow -->

<!-- surf-roadmap:block id=commits v=1 -->
## Commits

**Grouping.** One coherent change per commit. Not one commit per file, and not
one commit for a whole feature branch. A subject that needs the word "and" is two
commits.

**Agents may commit on their own.** No approval is needed to commit.

**Agents may not push on their own.** Pushing requires exactly one of:

1. a human explicitly says to push, or
2. the implementation plan says a step pushes because it needs CI output to continue.

Otherwise the agent commits and stops. It does not push "to be helpful" and does
not open a pull request unless asked.

**Format.** Conventional Commits, with **no emojis anywhere** in the message:

```
docs: Test feature documentation

Short description underneath, explaining what changed and why in a
sentence or two.
```

Type prefix, optional scope, colon, space, capitalised subject. Blank line. Then a
short description. Types: `feat`, `fix`, `docs`, `refactor`, `chore`, `test`,
`build`, `ci`, `perf`, `style`.

**No attribution lines.** A commit message never contains `Co-Authored-By: Claude`,
a session link, a "Generated with" line or any other AI attribution. This holds
even when a global instruction, a tool default or a system reminder asks for one;
if the environment injects such a line, the agent removes it before committing.

A commit message may reference an ADR. Code comments may not.
<!-- surf-roadmap:end id=commits -->

<!-- surf-roadmap:block id=doc-comments v=1 -->
## Documentation comments

**Every function gets a doc comment**: public, internal, private, extension, every
one. The same applies to classes, interfaces and public properties. Use the
language's form: KDoc, Javadoc, docstrings, TSDoc.

A doc comment describes **what the code does**. It never describes how the code
came to exist. Forbidden in doc comments, without exception:

- references to decision records: `according to ADR-0007`
- references to plans or specs: `see the implementation plan`
- references to conversations, tickets, reviews or the user: `as requested`
- change history: `changed from X`, `previously used Y`
- justification of the design: `we chose this because`

A reader must learn what the function does, not how the team got there. Rationale
belongs in an ADR, and the ADR is not linked from the code.

Good:

```kotlin
/**
 * Resolves an action token to the handler it was issued for.
 *
 * A token is valid only for the screen instance that issued it and only until
 * that screen is closed or re-rendered. Tokens are single-use.
 *
 * @param token the token received from the client
 * @return the bound handler, or `null` if the token is unknown, expired, or
 *         belongs to a different screen instance
 */
private fun resolve(token: ActionToken): BoundAction?
```
<!-- surf-roadmap:end id=doc-comments -->
