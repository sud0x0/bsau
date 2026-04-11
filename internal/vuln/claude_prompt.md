First, count the total number of entries currently in internal/vuln/mapped-values.json
and report that number. Before doing anything else, fetch https://formulae.brew.sh/api/formula.json and report the total number of Homebrew formulae. Also count and report the current number of entries in internal/vuln/mapped-values.json.

Second, update internal/vuln/mapped-values.json with mappings for any Homebrew
packages not already in the file. Use the same format and rules as the existing
entries. Do not modify or remove any existing entries. Only add new ones.

Do not skip any packages. The coverage percentage ((count after / total Homebrew formulae) * 100) must be 100%

Rules:
- osv_ecosystem must be a valid OSV ecosystem string, or empty string if unknown
- osv_package_name: exact name in the ecosystem, empty string if unknown
- cpe_vendor and cpe_product: NVD CPE dictionary strings, lowercase, empty if unknown
- confidence: high, medium, or low — prefer empty string over low confidence
- Update generated_at to today's date

Third, after updating the file, count the total number of entries in the updated
file and report:
- Total Homebrew formulae (from API)
- Count before update
- Count after update
- Number of new entries added
- Coverage percentage: (count after / total Homebrew formulae) * 100
- Confirm every entry in the file has at least one of: osv_ecosystem, cpe_vendor,
  or cpe_product populated — if any entry has all three empty, list them so they
  can be reviewed or removed
