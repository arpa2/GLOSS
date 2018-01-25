# GLOSS: Grep Logs on Open Source Systems

> *Log files are a rich information resource that can be a
> real nuisance to mine.  GLOSS works to standardise their
> structure, and simplify jumping between related selections.*

The GLOSS tool analyses log files by parsing their standard part
and, when available, use a specific driver to parse the free-text
portion even further.

The result of this work is a set of variable assignments.
Some variables may stem from the general part, others from the
analysis of the free-text form.

Using options, it is simple to select lines from log files and
see only those; selection criteria can describe processes, times,
and host names.  These are helpful because they speed up the
selection process.  You can quickly select last Wednesday's
logs by the Postfix smtp daemon, for instance.

But variables allow a much more refined method of selection.
GLOSS supports a style of interaction that is similar to an
SQL-styled `select`, `where`, `from` based on these variables.
The fixed portions of the syntax also all end up in variables
to simplify this process.  In general, the specific form of
selection is fast and the query form is general.

Very often, the variables to set can be derived from others.
Given a variable to look for, one or more drivers may be
selected.  Given a driver, one or more log files may be
selected.  GLOSS tries to be clever about these things,
but its choices may not always be the ones you would like.
The verbose option informs you about its clevernesses, and
you can always choose to specify things yourself when the
results are ambiguous, too broad or otherwise unfit.  You
get to choose how far you want to trim down the reports
to gloss over, basically.

**GLOSS is not finished** but it may already be useful
to you.  Please see the TODO file or the `--help` output
to learn more about its current state.


## Example Use

One very good example of using GLOSS is the Postfix MTA.
It logs copious information with recurring values such as
email addresses and queue identifiers.  Let's say that the
queue shows an email with a queue identity `5466A1D54E` that
we wish to explore in more detail.  To do this, we would
invoke

```
gloss -w postfix.qid=5466A1D54E
```

This invocation sets off the following reasoning:

  * The variable scope `postfix` must be loaded.  This defines
    a number of variables, including `qid`.  It does not
    itself define matching rules, as this is purely a scope
    for variables.

  * This variable scope is a descriptor that references a
    number of proc drivers to load, which are added to the
    given (empty) list.

  * These additional proc drivers specify regular expressions
    and corresponding variable lists that match it.  Those
    that bind the requested variable `qid` are incorporated.

  * The program can now run with a limited number of proc
    drivers and for those it will only match the regular
    expressions that bind the `qid` variable.  On each, it
    investigates the value and, if matching, it will display
    that line in the desired format.

We may look through the entries manually, which is quite
pleasant when viewing HTML over HTTP because we can click
on variable bindings; but the command line also allows us
to make a direct query for the information that we need:

```
gloss -w postfix.qid=5466A1D54E -s postfix.from
```

This would print the value for that variable; in the current
form as part of the complete logline, but another output form
may also be used.

Either way, we now have an email address to continue looking
for, and we can continue in the same vain,

```
gloss -w postfix.from=john@exmaple.com
```

We might output information as a CSV listing, for import
into all sorts of software.  Or we can just continue to
gloss over it ourselves.

Had we chosen to represent the outut as HTML over HTTP, then
we could have clicked on the address and seen it enacted.
Some interaction would be possible to keep or drop the
prior selection of the `postfix.qid` match; this allows a
choice between tightening or broadening the search.

The latter query would be the broading search, while a
tighter search would be based on both `-w` conditions.
When this is run, a much smaller set of variable-binding
regular expressions from the proc drivers is considered.

Note that a smaller number of regular expressions helps
to speed up the processing of large logfiles.  This is
in the interest of interactive use of the tool, for
instance as HTML over HTTP.  Much of GLOSS follows the
line of reasoning that a well-prepared query can do
better when sifting through a large logfile.


