# Reporting Workflow

1. Run a read-only scan against an authorized target.
2. Export the results as JSON or HTML.
3. Group findings by severity and affected component.
4. Validate important findings manually.
5. Track remediation and rescan after fixes.

Page-based checks also include an informational finding when the final page
response is an HTTP 4xx or 5xx status. This helps distinguish a complete page
scan from a response such as a missing page or server error.

Both formats are written as UTF-8. The HTML report includes a labeled findings
table so assistive technologies can identify each column.
