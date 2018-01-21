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

