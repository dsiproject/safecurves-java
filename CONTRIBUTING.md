# Contributing to Safecurves-Java

Contributions to Krypton should abide by the following guidelines:

## Git Conventions

### Branching Conventions

This project uses the
 [GitFlow workflow](https://datasift.github.io/gitflow/IntroducingGitFlow.html).

Specifically, the following branches are privileged, and should not be modified
directly:

* `master`: This branch is for release tracking.  Only release candidate
  branches should be merged in here.
* `devel`: This branch tracks current development status.  Feature branches
  should be merged in here.

To work on a feature, create a feature branch from `devel` and start working.
When you finish, submit a merge request, have it reviewed, and ultimately merge
it back in.

### Repository Integrity

The following rules should be observed for all commits and merges:

* All commits must be signed.  See
  [this guide](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work) for
  information on signed commits.

* All feature branch merges must have a corresponding issue number.

* Whenever a feature branch is merged, `devel` must be tagged with the issue
  number, and the issue should be closed.

## Code Conventions

The following rules should be observed with regard to code:

* Linewrap at 80 columns.
* No hard tabs.
* No trailing whitespace.
* Observe standard Java checkstyle guidelines.
* No doclint warnings.
* Javadoc everything
* Key functionality should have more descriptive javadoc than just "boilerplate"
* Include tests for nontrivial functionality
* All tests must pass all the time
* Abide by
  [Java secure code conventions](http://www.oracle.com/technetwork/java/seccodeguide-139067.html)
* Use the `final` keyword liberally in variable and parameter definitions.
* Mark all overrides with `@Override`

Cryptographic implementations must also observe the following rules:

* No data flow from sensitive material (keys, plaintexts) to control-flow decisions.
* Avoid data flow from sensitive material to memory accesses wherever possible.
* Zero out any copies of sensitive material.
* Core cryptographic algorithms should be done in a "C-like" fashion, in `static`
  methods using primitives and arrays as much as possible.
