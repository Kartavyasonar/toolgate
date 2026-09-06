# InvokeCordon Scan Report

**Target:** `http://127.0.0.1:8000/mcp`

**Score:** 0/100 (**F**)

## Findings (8)

| Tool | Rule | Message |
| --- | --- | --- |
| fetch_url | dangerous_tool_name | tool name contains "fetch_url" |
| fetch_url | permissive_schema | input schema sets additionalProperties to true |
| fetch_url | suspicious_description | description contains "http://" |
| read_file | dangerous_tool_name | tool name contains "file" |
| read_file | permissive_schema | input schema sets additionalProperties to true |
| run_command | dangerous_tool_name | tool name contains "command" |
| run_command | permissive_schema | input schema sets additionalProperties to true |
| run_command | suspicious_description | description contains "ignore previous" |

## Deductions

| Rule | Points |
| --- | --- |
| dangerous_tool_name | -60 |
| permissive_schema | -30 |
| suspicious_description | -20 |
