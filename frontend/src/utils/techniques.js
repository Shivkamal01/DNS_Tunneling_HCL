/**
 * MITRE ATT&CK techniques that describe the behaviour this engine detects.
 *
 * These are mappings, not detector output — the scoring engine does not know
 * which technique an operator intended. The console labels them as such so an
 * analyst does not mistake a heuristic tag for a confirmed attribution.
 */
export const DNS_TUNNELING_TECHNIQUES = [
  {
    id: 'T1071.004',
    name: 'Application Layer Protocol: DNS',
    tactic: 'Command and Control',
    note: 'C2 traffic encoded into DNS question names or TXT payloads.',
    url: 'https://attack.mitre.org/techniques/T1071/004/',
  },
  {
    id: 'T1048.003',
    name: 'Exfiltration Over Alternative Protocol',
    tactic: 'Exfiltration',
    note: 'Data staged into high-entropy labels and sent through a resolver.',
    url: 'https://attack.mitre.org/techniques/T1048/003/',
  },
  {
    id: 'T1572',
    name: 'Protocol Tunneling',
    tactic: 'Command and Control',
    note: 'A covert channel carried inside otherwise permitted DNS traffic.',
    url: 'https://attack.mitre.org/techniques/T1572/',
  },
];

/**
 * Only show the two techniques the evidence actually supports. The generic
 * protocol-tunneling entry is useful context but would overstate a single
 * suspicious query, so it is exposed separately for the incident view.
 */
export const PRIMARY_TECHNIQUES = DNS_TUNNELING_TECHNIQUES.slice(0, 2);
