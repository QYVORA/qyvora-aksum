# assess.qs — a runnable example of the shared QYVORA scripting engine driving
# aksum's offline binary analysis pipeline.
#
#     aksum script run examples/assess.qs
#
# aksum is offline and read-only: point it at a binary you are authorized to
# analyze. This example uses the committed minimal ELF fixture.

# Select the binary under analysis and the minimum reported severity.
set analyze.target -> "examples/fixtures/sample.elf"
set analyze.severity -> "info"

# Run the full static assessment pipeline. Capability ids such as
# "analysis.strings" name an analysis area; running one runs the pipeline that
# covers it.
run assess

# Read live properties from the completed run via $(...).
echo -> "target    = $(target.path)"
echo -> "format    = $(target.format)/$(target.arch)"
echo -> "sha256    = $(target.sha256)"
echo -> "functions = $(result.functions)"
echo -> "findings  = $(result.findings)"

# Show capability metadata and write a JSON report artifact.
show analysis.strings
report -> "aksum-report.json"

echo -> "done"
