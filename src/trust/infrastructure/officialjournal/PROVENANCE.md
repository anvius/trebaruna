# Anchors of the EU list of the lists

`C-2026-1944.pem` holds the six certificates the Official Journal of the
European Union published in notice C/2026/1944
(<https://eur-lex.europa.eu/eli/C/2026/1944/oj>) as the ones the Commission
signs the EU list of the lists with. They were read from that notice on
9 November 2026, over HTTPS from eur-lex.europa.eu, and checked against the
list itself (<https://ec.europa.eu/tools/lotl/eu-lotl.xml>) the same day: the
list names that notice first among its announcements, its pointer to itself
publishes these six certificates, and it was signed with the second.

| SHA-256 | Subject | Valid until |
|---|---|---|
| `C0641C4F7D56C431B1C924742DB7FCE9C1EEF7D7FD212113A2768486B3ABCDC5` | IOANNA KALOGEROPOULOU, European Commission | 2029-11-23 |
| `E0A620FBB6747362BB933AC44169D676A553444716CF5F31605F12A22B8396B1` | EUROPEAN COMMISSION, DG DIGIT (signed the list on 9 November 2026) | 2027-11-17 |
| `DF7E29360C34B2B8D6D5F40325C1D4D12C9922CECD33B7407674A74B2B3CA1E5` | VICENTE ANDREU NAVARRO, European Commission | 2027-05-06 |
| `B63D416744E7098BF9EC2CAA596A93BC2468E37F8284BA65ECC061711BCBAA18` | APOSTOLOS APLADAS, European Commission | 2027-04-26 |
| `236103F03A8031AE8F47F9059BF8DE38564CDBFEBEDDE4A597D50F8980AA653B` | EUROPEAN COMMISSION, DG for Digital Services | 2029-12-17 |
| `D2064FDD70F6982DCC516B86D9D5C56AEA939417C624B2E478C0B29DE54F8474` | Patrick Kremer | 2028-05-30 |

When the Commission changes its keys it publishes a pivot list, signed with
an announced key, naming the new ones; trebaruna follows the pivots the list
names after this notice. When a newer notice replaces this one, the list no
longer names it and `trust sync` refuses the list until these anchors are
updated from the new notice, the same way.
