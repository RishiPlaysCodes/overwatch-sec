"""
social_engineering — AUTHORIZED security-awareness simulation analysis.

This module does NOT send phishing, host lures, or collect real credentials. It
*analyzes the results* of an authorized awareness campaign that you ran through a
sanctioned platform (or a controlled dummy-credential exercise), and reports
human-risk metrics: click rate, credential-submission rate (dummy only),
reporting rate, MFA-awareness, and policy gaps.

Hard safety rules (enforced by the analyzer + policy gate):
  - never generates or sends campaigns
  - never collects/stores real credentials (submissions are counts only)
  - only runs when policy.social_engineering is explicitly enabled
"""
