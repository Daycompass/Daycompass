#!/usr/bin/env bash
# Roadmap project IDs for `gh project item-add` / `item-edit`, looked up once
# so sessions don't have to rediscover them. IDs are not secrets.
#
# TODO: not yet populated. The `gh` auth token used by Claude Code in this
# repo is missing the `project` scope (run `gh auth refresh -s project`),
# so these haven't been looked up yet. Once that's done, fill in:
#   gh project list --owner @me
#   gh project field-list <number> --owner @me
# and hardcode the values below.

set -euo pipefail

PROJECT_OWNER="@me"
PROJECT_NUMBER=""       # TODO
PROJECT_ID=""           # TODO: gh project view <number> --owner @me --format json | jq -r .id
STATUS_FIELD_ID=""      # TODO
STATUS_OPTION_TODO=""        # TODO
STATUS_OPTION_IN_PROGRESS="" # TODO
STATUS_OPTION_DONE=""        # TODO
