# Security Specification — ESD Market Firestore

## 1. Data Invariants
1. **Default Deny**: No document in Firestore is readable or writable unless explicitly matched and authorized.
2. **Public Catalog Read-Only**: Anonymous visitors may only read `/store/catalog` (`get`) and `/catalog_chunks/{chunkId}` (`get` / bounded `list` where `0 <= index < 20`). They can never write, delete, or read private collections.
3. **Zero Client Secret**: Admin password/PIN never resides in client HTML/JS. It lives exclusively in `/store_private/admin_auth`, which is readable and writable ONLY when `isAdmin()` passes.
4. **Verified Google Identity Gate**: `isAdmin()` requires `request.auth != null && request.auth.token.email_verified == true` AND membership in `/admins/{uid}` OR active `/admin_emails/{lowercase_email}`.
5. **Bounded Catalog Chunks & Product Images**: `/store/catalog` arrays (`cats`, `ecat`, `colors`) are capped at `<= 40` entries; `/catalog_chunks/{chunkId}` `items` array is strictly capped at `<= 100` items; catalog chunks store image URLs or `fbimg://{imageId}` links (never raw Base64 inside chunk docs). Uploaded compressed images in `/product_images/{imageId}` are strictly bounded (`<= 250 KB`, admin-only write/delete, `allow list: if false`).
6. **Strict Schema & Server Timestamps**: Every write enforces `hasAll` + `hasOnly` (no shadow ghost fields), field type checks, `.size()` caps, and `request.time` server timestamp equality.
7. **Self-Removal & Email Spoofing Protection**: Admins cannot delete their own UID or own allowlist email; unverified email tokens are unconditionally rejected; users can only check their own `admin_emails/{email}` or `admins/{uid}` doc.
8. **Order PII Isolation & Integrity**: Customers can only `create` initial orders in `/orders/{orderId}` (`status == 0`, `returnedTotal == 0`, `discountDeduction == 0`, `paymentPaid == false`, `total == subtotal > 0`, `createdAt == request.time`). Reading (`get`/`list`), updating (returns, deductions, payment collection, status), and deleting orders are strictly restricted to `isAdmin()`.

## 2. The "Dirty Dozen" Attack Payloads
1. **Unauthenticated catalog write**: `setDoc('/store/catalog', {...})` with `auth = null` -> `PERMISSION_DENIED`.
2. **Signed-in non-admin Google user writing catalog**: verified Gmail not in `admins`/`admin_emails` attempts `setDoc('/store/catalog', {...})` -> `PERMISSION_DENIED`.
3. **Email spoofing with `email_verified: false`**: token matches allowlisted email but `email_verified: false` -> `PERMISSION_DENIED`.
4. **Non-admin reading `/store_private/admin_auth`**: signed-in regular user calls `getDoc('/store_private/admin_auth')` -> `PERMISSION_DENIED`.
5. **Non-admin listing `/admin_emails`**: regular user calls `getDocs('/admin_emails')` -> `PERMISSION_DENIED`.
6. **Self-privilege escalation in `/admins/{uid}`**: regular user tries `setDoc('/admins/' + uid, { role: 'admin', ... })` -> `PERMISSION_DENIED`.
7. **Shadow ghost field on `/store/catalog`**: admin writes extra `isHacked: true` field -> `PERMISSION_DENIED` (`hasOnly` rejects).
8. **Client timestamp forgery**: admin writes `updatedAt: new Date(0)` instead of `serverTimestamp()` -> `PERMISSION_DENIED`.
9. **Identity spoofing on `updatedBy`**: admin writes `updatedBy: 'other_uid'` -> `PERMISSION_DENIED`.
10. **Unbounded array / Denial-of-Wallet**: admin writes `items` with 101 items or `cats` with 41 entries -> `PERMISSION_DENIED`.
11. **ID poisoning**: read/write to `/store/catalog/../../etc` or 200-char doc ID -> `PERMISSION_DENIED`.
12. **Plaintext PIN overwrite on `/store_private/admin_auth`**: admin tries writing `{ pin: '3317167' }` instead of 64-char hex `pinHash` -> `PERMISSION_DENIED`.
13. **Guest/Non-Admin PII Scrape on `/orders`**: guest or regular user calls `getDoc('/orders/ord_1')` or `getDocs('/orders')` -> `PERMISSION_DENIED`.
14. **Tampered Initial Order State**: visitor creates order with `status: 3`, `paymentPaid: true`, `total: 0`, or `isAdminOverride: true` -> `PERMISSION_DENIED`.

## 3. Red Team Audit Summary
- **Identity Spoofing**: Closed via `updatedBy == request.auth.uid` and `emailId == request.auth.token.email.lower()`.
- **Email Spoofing**: Closed via `request.auth.token.email_verified == true` inside `isVerifiedUser()`.
- **PII / Secret Isolation**: `/admin_emails` and `/store_private` reject non-admin `list`; `/store_private/admin_auth` rejects all non-admin reads/writes; `/admins/{uid}` and `/admin_emails/{emailId}` restrict `get` strictly to the matching user or an admin; `/orders/{orderId}` restricts all `get`, `list`, `update`, and `delete` strictly to `isAdmin()`.
- **Query Enforcer**: `/catalog_chunks` `allow list` validates `resource.data.index >= 0 && resource.data.index < 20` with zero `get()`/`exists()` inside `list`; `/orders` `allow list` is restricted solely to `isAdmin()`.
- **Shadow Update & Value Poisoning**: Closed via `isValid*(incoming())` wrapped on both `create` and `update` alongside `hasAll`/`hasOnly`/`affectedKeys().hasOnly()`.
