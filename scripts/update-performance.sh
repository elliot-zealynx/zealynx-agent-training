#!/bin/bash

# Agent Performance Update Script
# Usage: ./scripts/update-performance.sh <agent> <contest-name> <findings-file>
# Example: ./scripts/update-performance.sh sol merkl agents/sol/shadow-audits/2026-02-10-merkl.md

set -e

AGENT=$1
CONTEST=$2
FINDINGS_FILE=$3

if [ -z "$AGENT" ] || [ -z "$CONTEST" ] || [ -z "$FINDINGS_FILE" ]; then
    echo "Usage: $0 <agent> <contest-name> <findings-file>"
    echo "Example: $0 sol merkl agents/sol/shadow-audits/2026-02-10-merkl.md"
    exit 1
fi

echo "🔄 Updating performance tracking for $AGENT after $CONTEST contest"

# Validate agent exists
if [ ! -d "agents/$AGENT" ]; then
    echo "❌ Error: Agent directory agents/$AGENT does not exist"
    exit 1
fi

# Validate findings file exists
if [ ! -f "$FINDINGS_FILE" ]; then
    echo "❌ Error: Findings file $FINDINGS_FILE does not exist"
    exit 1
fi

# Create backup
echo "📋 Creating backup..."
cp "agents/$AGENT/performance.md" "agents/$AGENT/performance.md.backup"

# Update timestamp
echo "⏰ Updating last modified timestamp..."
sed -i "s/\*\*Started Tracking:\*\*.*/\*\*Last Updated:\*\* $(date '+%B %d, %Y')/" "agents/$AGENT/performance.md"

# Add git commit
echo "📝 Committing changes..."
git add "$FINDINGS_FILE"
git add "agents/$AGENT/performance.md"
git add "tracking/agent-performance-tracker.md" 2>/dev/null || true

git commit -m "📊 $AGENT performance update: $CONTEST contest

- Added findings from $CONTEST contest
- Updated individual performance tracking
- Results analysis and lessons learned documented

File: $FINDINGS_FILE"

echo "✅ Performance tracking updated for $AGENT"
echo "📤 Pushing to repository..."
git push

echo "🎯 Next steps for $AGENT:"
echo "   1. Review false positives and update knowledge base"
echo "   2. Study missed findings for new patterns" 
echo "   3. Update central performance tracker with new metrics"
echo "   4. Prepare for next shadow audit with improved methodology"