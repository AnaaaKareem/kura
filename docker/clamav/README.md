# ClamAV virus scanning for Kura

Every uploaded file goes to ClamAV **before** it is saved anywhere:

```
browser ─► nginx ─► WAF ─► Django kura/files.py validate_and_save_upload()
                              │ 1. size check (1 byte .. 25 MiB)
                              │ 2. scan_file_for_malware(): bytes ─► clamav:3310 (INSTREAM)
                              │      "stream: OK"            → continue
                              │      "stream: <name> FOUND"  → quarantine + reject
                              │      no answer / error       → reject (fail closed)
                              │ 3. check_signature_age(): warn if signatures > 3 days old
                              │ 4. real file type (python-magic) against the allowlist
                              ▼ 5. SHA-256, then save StoredFile + FileContent
```

ClamAV is on the internal `backend` network, so only Django can reach it, and
on `clamav_updates`, an outbound-only route that lets `freshclam` download
new signatures. No port is published to the host.

## Kura's scanner policy (`clamd.conf`)

| Setting | What it rejects | Example detection |
|---|---|---|
| (signatures) | Known malware | `Eicar-Test-Signature`, `Win.Trojan...` |
| `AlertEncrypted yes` | Password-protected ZIPs, PDFs and Office files, because ClamAV can't look inside | `Heuristics.Encrypted.Zip` |
| `AlertOLE2Macros yes` | Office files with VBA macros | `Heuristics.OLE2.ContainsMacros` |
| `AlertExceedsMax yes` | Files too big or too deeply packed to scan completely (for example a zip bomb) | `Heuristics.Limits.Exceeded...` |
| `StreamMaxLength 26M` | Nothing extra: room for Kura's 25 MiB limit | |

The user only ever sees "The uploaded file failed security scanning." They
never see the detection name.

If the signatures are **more than 3 days old**, uploads still work, but Django
writes a warning to the security log:
`ClamAV virus signatures are N days old ... Check freshclam updates.`
If ClamAV **can't be reached**, every upload is refused: "Antivirus service is
unavailable. Upload rejected for safety." These files are not quarantined.

## Quarantine

A rejected file is kept for **7 days** in `quarantined_files` (model
`QuarantinedFile`) with:
- who uploaded it
- the file name
- its size and SHA-256
- the detection name
- the bytes

- **Saved even when the upload is rolled back.** It's saved through a second
  database connection named `quarantine` (`config/settings.py`). That
  connection commits on its own, so the record survives when the upload view's
  transaction is rolled back.
- **Never downloadable.** The normal download views only serve `StoredFile`.
- **Admins only.** Admins see the list at **Quarantine** in the menu
  (`/admin/quarantine/`): the details and a Delete button that needs POST, the
  CSRF token and a ticked confirmation box. There's no download. Look the
  SHA-256 up on a malware database such as VirusTotal instead.
- **Security log.** Every rejection writes one line:
  `Upload rejected and quarantined: user=<id> file='<name>' size=<n> sha256=<hash> detection=<name>`.
  The file name is quoted and escaped, so a crafted name can't forge extra log lines.
- **Cleanup.** `python manage.py purge_quarantine` (daily) deletes records
  older than 7 days. The log lines stay.

## Checked live (6 November 2026)

| Test | Result |
|---|---|
| Effective config (`clamconf`) | `AlertEncrypted`, `AlertOLE2Macros`, `AlertExceedsMax` = yes; `StreamMaxLength` = 27262976 |
| EICAR test file | rejected, quarantined as `Eicar-Test-Signature` |
| ZIP with a password | rejected, quarantined as `Heuristics.Encrypted.Zip` |
| Clean PDF | stored |
| Quarantine records when the upload ran inside `transaction.atomic()` | kept |
| Signature age check | no warning (signatures current) |
| Admin page | `200`, shows the detection and SHA-256, no file bytes; Student gets `403`; GET on delete gets `405`; confirmed POST deletes |
| ClamAV stopped, clean upload | rejected, not quarantined, not stored |

Not tested live: an Office file with real macros. There was no sample file to
hand. The setting is confirmed active with `clamconf`.

## Try it yourself

```bash
# The scanner settings in use
docker exec kura-clamav clamconf -n | grep -E 'AlertEncrypted|AlertOLE2Macros|AlertExceedsMax'

# Upload the EICAR test file anywhere in Kura, then as an Admin open
# Quarantine in the menu. It is listed as Eicar-Test-Signature.
```
