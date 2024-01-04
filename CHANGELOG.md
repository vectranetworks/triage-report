# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.2.1 - 2024-01-04

### Added

- Automatically stripping the end **/profile** from the url if it is present

## 1.2.0 - 2023-06-23

### Changed

- collect_rules now takes a list of rules
- collect_groups now takes a list of groups
- Brandon discovered and fixed the bug with rules > 6months. Converted Generator
to a list since the generator was running dry

## 1.1.0 - 2023-01-12

### Added

- Colorized output
- Better error handling

### Changed

- Updated the template
- Script will only prompt for URL or Token if they are not given
- Reports now go to **./reports/** as opposed to the local directory of this project

## 1.0.4 - 2022-03-11

### Added

- Intial commit to GitHub
- Grab data from brains and mail merge to a triage report word doc
