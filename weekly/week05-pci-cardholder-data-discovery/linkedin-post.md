The worst file on a payment company's file share is rarely in the CDE. It's usually a chargeback spreadsheet.

For week 5 of my 53-project series, I built a PCI DSS cardholder data discovery scanner: a defensive "CVV/PAN finder" that looks for stored card numbers and the sensitive authentication data that must never be kept after authorisation. Every hit is masked, and the output is a Requirement 3 remediation plan by location.

On a synthetic retailer's file share, the findings followed a familiar pattern:

- A chargeback export kept the CVV2 column "for evidence". Disputes need the last four and an auth code, not the CVV.
- DEBUG logging on the checkout API wrote full card bodies, and so did the rotated .gz log. Fixing the logger without purging archives and the SIEM leaves the problem in place.
- The tokenisation "fallback" path logged the clear PAN. Error paths leak.
- A POS SQLite queue only showed its PANs when read row by row. A strings pass glues the fields together.
- An expired exception quietly brought a legacy CRM export back into scope.

What I'd tell any PCI programme: 12.5.2 asks for all locations of account data. A file you couldn't open isn't clean. It's a coverage gap, and it belongs in the report.

All data is synthetic, using published test card numbers only.

https://github.com/mshshuvo/Cyber-Projects/tree/main/weekly/week05-pci-cardholder-data-discovery

#PCIDSS #DataProtection #Payments #GRC #CyberRisk
