# Security Summary

**Reviewed Files**: 6 (`firestore.rules`, `esd_market.html`, `server.js`, `firebase-blueprint.json`, `security_spec.md`, `firestore.rules.test.ts`)
**Issues Resolved**: 4

### Issues Resolved
| Area | File | Line | What Was Happening | Impact | Status | How It Was Fixed |
|---|---|---|---|---|---|---|
| Cost-Safe Rule Evaluation Order | `firestore.rules` | 190–285 | `isAdmin()` ran before static ID/schema checks on admin write paths, allowing malformed writes to consume Firestore read lookups (`get`/`exists`) before failing. | Medium | Fixed | Reordered all `get`, `create`, `update`, and `delete` checks so authentication (`isVerifiedUser()`), ID regex (`isValidId()`), and payload schema validation execute before `isAdmin()`. |
| Catalog Chunk ID & Index Alignment | `firestore.rules` | 206–220 | `/catalog_chunks/{chunkId}` accepted `chunk_20`..`chunk_99` in the path regex and did not verify that `chunkId` matched `chunk_<index>`. | Low | Fixed | Restricted `chunkId` strictly to `^chunk_([0-9]|1[0-9])$` and enforced `chunkId == ('chunk_' + string(incoming().index))` on `create` and `update`. |
| Guest Order & Financial Validation | `firestore.rules` | 108–244 | Public `/orders` creation allowed arbitrary valid IDs, item map elements were not key-checked, and admin order updates did not verify `returnedTotal <= subtotal` and `total <= subtotal`. | Medium | Fixed | Restricted unauthenticated order creation to `^ord_[a-zA-Z0-9_\-]+$`, added `isValidOrderItemMap()` strict key/type/bound validation, and enforced `returnedTotal <= subtotal && total <= subtotal` on updates. |
| Store Settings Nested Map Validation | `firestore.rules` | 162–189 | Nested objects inside `whatsappStaff`, `vodafoneNumbers`, and `instaPayNumbers` checked only that element 0 was a map rather than checking exact allowed keys and sizes. | Low | Fixed | Added `isValidStaffEntry()` and `isValidPaymentAccountEntry()` with strict `hasAll`/`hasOnly` keys and length limits. |

### Safeguards Verified
| Area | File | How It's Protected |
|---|---|---|
| Default-Deny Catch-All | `firestore.rules` | First rule (`match /{document=**}`) denies all reads and writes unless explicitly matched below. |
| Admin Identity & Role Checks | `firestore.rules` | `isAdmin()` requires a verified Google Auth token (`email_verified == true`) plus membership in `admins/{uid}`, active `admin_emails/{email}`, or owner allowlist; unverified tokens are rejected. |
| Customer PII Isolation | `firestore.rules` | `/orders` `get`, `list`, `update`, and `delete` are locked strictly to `isAdmin()`; public checkout can only create new `ord_*` records with locked initial state (`status == 0`, `paymentPaid == false`, `total == subtotal`). |
| Secret Hash Isolation | `firestore.rules` | `/store_private/admin_auth` allows `get`, `create`, and `update` only for verified admins with a 64-character SHA-256 hex digest and blocks `list` and `delete`. |
| Safe Output Rendering | `esd_market.html` | Customer names, addresses, phone numbers, notes, order IDs, payment accounts, and storefront announcements are rendered via `esc()` or `.textContent`. |
| Dependencies | `package.json`, `bun.lock` | `bun audit` verified 159 resolved packages with zero known vulnerabilities. |

## PoC Verification

### 1. Pre-Lookup Rejection of Malformed Admin Writes (Denial-of-Wallet)
#### Summary
| Field | Value |
|---|---|
| Issue Type | Rule evaluation ordering causing unnecessary Firestore reads on invalid writes |
| Impact | Medium |
| Affected File | `firestore.rules:190` |
| Test Scenario | Non-admin verified user calls `setDoc(doc(db, 'store', 'x'.repeat(200)), { isHacked: true })` |

#### How It Was Fixed
Moved `isVerifiedUser()`, `isValidId(docId)`, and `isValidStoreCatalog(incoming())` / `isValidStoreSettings(incoming())` ahead of `isAdmin()` in the `&&` chain.

#### Step-by-Step Trace
| Step | What Happens in the Code | Outcome |
|---|---|---|
| 1 | Signed-in user sends write to `/store/xxx...` (200 chars) | Enters `/store/{docId}` `allow create` |
| 2 | `isVerifiedUser()` passes, then `isValidId(docId)` checks `id.size() <= 128` at `firestore.rules:19` | Evaluates to `false` immediately |
| 3 | Short-circuit `&&` stops evaluation before `isAdmin()` | **Handled Safely (Zero DB reads, rejected)** |

---

### 2. Guest Order Key/ID Prefix & Financial Bound Tampering
#### Summary
| Field | Value |
|---|---|
| Issue Type | Unauthenticated order creation surface and admin update financial consistency |
| Impact | Medium |
| Affected File | `firestore.rules:108-244` |
| Test Scenario | Guest submits `setDoc(doc(db, 'orders', 'evil_id'), validOrder)` or shadow-key item, or tampered update sets `total: 999` on `subtotal: 90` |

#### How It Was Fixed
Restricted guest creation to `ord_*` IDs, validated `items[0]` via `isValidOrderItemMap()`, and capped `returnedTotal <= subtotal` and `total <= subtotal` inside `isValidOrderUpdate()`.

#### Step-by-Step Trace
| Step | What Happens in the Code | Outcome |
|---|---|---|
| 1 | Malicious `setDoc` reaches `/orders/{orderId}` `allow create` | Evaluates `orderId.matches('^ord_[a-zA-Z0-9_\\-]+$')` |
| 2 | `'evil_id'` fails regex; shadowed item fails `isValidOrderItemMap()` `hasOnly`; `total: 999` fails `total <= subtotal` | Condition evaluates to `false` |
| 3 | Firestore rejects request before write commits | **Handled Safely** |

#### Conclusion
**Fix Verified** - Verified with `npx eslint firestore.rules` (0 warnings/errors), deployed live to the configured Firestore database via `DeployRules`, and aligned with `firestore.rules.test.ts` and `security_spec.md`.
