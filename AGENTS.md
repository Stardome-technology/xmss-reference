<!-- git-workflow: v1 -->
## Git workflow
- forge: github                # github | gitlab
- status: fork-submodule       # production | development | fork-submodule
- origin: this fork            # writable: push work branches here, open MRs/PRs here
- upstream: https://github.com/XMSS/xmss-reference.git  # documentation only — the repo this fork was cut from
  # No clone carries an `upstream` git remote; agents never fetch or push it.
  # If no live upstream exists: "none (stripped snapshot)".
- integration branch: stardome-stripped   # stardome-stripped | stardome-stripped-v2
  # protected — never push directly
- the inherited main/master branch (present on origin from the upstream history) is
  sync staging: it is updated ONLY by the human two-step sync below — agents never
  commit, merge, or rebase it
- submodules are checked out DETACHED at the pinned commit: never commit on a detached
  HEAD — always spin the work branch from origin/<integration-branch> first
- one unit of work = one short-lived branch, spun from origin/<integration-branch>:
  - feat/<short-descriptive-name>   # features; OpenSpec change ⇒ feat/<change-id>
  - bug/<short-descriptive-name>    # bug fixes
- merge back: squash MR/PR into <integration-branch>, then delete the work branch
- consumption: the parent repo bumps the submodule pointer to the merged commit —
  do not merge the submodule branch inside the parent
- NEVER:
  - push directly to a protected branch (incl. upstream main/master)
  - force-push a protected branch
  - reuse an already-merged branch
  - commit directly into main/master/dev/stardome-stripped*