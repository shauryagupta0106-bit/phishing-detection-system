# Project notes for submission

## Problem
Phishing messages often rely on deceptive URLs and social-engineering language. Users need a simple way to inspect suspicious content without opening it.

## Objective
Build a tool that accepts a URL or email text and classifies it as likely safe, needs review, or likely suspicious.

## Methodology
1. Normalize input.
2. Extract URL structure or email indicators.
3. Apply explainable heuristic rules.
4. Add risk points for detected signals.
5. Clamp the score to 0–100.
6. Convert score into Low/Medium/High risk.
7. Display the individual indicators to the user.

## Important limitation
A heuristic score is not ground truth. A legitimate URL can look unusual, and a sophisticated phishing URL can evade simple rules. The project should therefore be presented as an educational detection prototype.

## Demo checklist
- Start the Flask server.
- Show the URL Analysis tab.
- Test a safe demo URL.
- Test a suspicious demo URL.
- Show the score and individual findings.
- Switch to Email Analysis.
- Test the sample phishing-style email.
- Run `pytest -q`.
