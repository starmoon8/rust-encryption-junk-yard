#!/bin/bash

USERNAME="chesslogic8"
PER_PAGE=100
PAGE=1

echo "Cloning all repositories for $USERNAME..."

while :; do
  REPOS=$(curl -s "https://api.github.com/users/$USERNAME/repos?per_page=$PER_PAGE&page=$PAGE" | grep -oP '"clone_url": "\K[^"]+')

  # Break if no repos returned
  if [ -z "$REPOS" ]; then
    break
  fi

  for REPO in $REPOS; do
    echo "Cloning $REPO"
    git clone "$REPO"
  done

  PAGE=$((PAGE + 1))
done

echo "All repositories cloned."