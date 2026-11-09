# Netflix Cookie Checker

Check if Netflix cookies (Netscape `.txt`) are still valid.

## Features

- Test cookies against Netflix
- Save results by **status / country**
- Clear filenames: `status_country_plan_UUID.txt`
- Default: export **alive** only
- Parallel checking

## Status

| Status | Meaning |
|--------|---------|
| **alive** | Login OK |
| **dead** | Invalid / redirected to login |
| **blocked** | HTTP 429 / 403 |
| **error** | Network or other error |

## Requirements

- Python 3.8+
- `requests`

```bash
pip install -r requirements.txt