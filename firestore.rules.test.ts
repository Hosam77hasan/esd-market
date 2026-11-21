/**
 * Firestore Security Rules Test Suite for ESD Market (Dirty Dozen Verification)
 * Run with @firebase/rules-unit-testing against the Firestore Emulator when testing locally.
 */
import { assertFails, assertSucceeds, initializeTestEnvironment } from '@firebase/rules-unit-testing';
import { readFileSync } from 'node:fs';
import { doc, getDoc, getDocs, setDoc, collection, serverTimestamp } from 'firebase/firestore';

export async function runDirtyDozenTests() {
  const testEnv = await initializeTestEnvironment({
    projectId: 'knowledgeable-pulsar-spd8p',
    firestore: { rules: readFileSync('firestore.rules', 'utf8') }
  });

  const adminUid = 'admin_uid_1';
  const adminEmail = 'elhosam77@gmail.com';
  const attackerUid = 'user_uid_2';
  const attackerEmail = 'guest@gmail.com';
  const validPinHash = 'a'.repeat(64);

  await testEnv.withSecurityRulesDisabled(async (ctx) => {
    const db = ctx.firestore();
    await setDoc(doc(db, 'admin_emails', adminEmail), {
      email: adminEmail,
      active: true,
      createdAt: new Date()
    });
    await setDoc(doc(db, 'store_private', 'admin_auth'), {
      pinHash: validPinHash,
      updatedAt: new Date(),
      updatedBy: adminUid
    });
  });

  const guestDb = testEnv.unauthenticatedContext().firestore();
  const attackerDb = testEnv.authenticatedContext(attackerUid, { email: attackerEmail, email_verified: true }).firestore();
  const spoofedDb = testEnv.authenticatedContext('spoof_uid', { email: adminEmail, email_verified: false }).firestore();
  const adminDb = testEnv.authenticatedContext(adminUid, { email: adminEmail, email_verified: true }).firestore();

  // Dirty Dozen assertions
  await assertFails(setDoc(doc(guestDb, 'store', 'catalog'), { cats: ['A'], ecat: ['🛒'], colors: ['#ffffff'], chunkCount: 1, productCount: 0, updatedAt: serverTimestamp(), updatedBy: 'none' }));
  await assertFails(setDoc(doc(attackerDb, 'store', 'catalog'), { cats: ['A'], ecat: ['🛒'], colors: ['#ffffff'], chunkCount: 1, productCount: 0, updatedAt: serverTimestamp(), updatedBy: attackerUid }));
  await assertFails(setDoc(doc(spoofedDb, 'store', 'catalog'), { cats: ['A'], ecat: ['🛒'], colors: ['#ffffff'], chunkCount: 1, productCount: 0, updatedAt: serverTimestamp(), updatedBy: 'spoof_uid' }));
  await assertFails(getDoc(doc(attackerDb, 'store_private', 'admin_auth')));
  await assertFails(getDocs(collection(attackerDb, 'admin_emails')));
  await assertFails(setDoc(doc(attackerDb, 'admins', attackerUid), { email: attackerEmail, role: 'admin', createdAt: serverTimestamp() }));
  await assertFails(setDoc(doc(adminDb, 'store', 'catalog'), { cats: ['A'], ecat: ['🛒'], colors: ['#ffffff'], chunkCount: 1, productCount: 0, updatedAt: serverTimestamp(), updatedBy: adminUid, isHacked: true }));
  await assertFails(setDoc(doc(adminDb, 'store', 'catalog'), { cats: ['A'], ecat: ['🛒'], colors: ['#ffffff'], chunkCount: 1, productCount: 0, updatedAt: new Date(0), updatedBy: adminUid }));
  await assertFails(setDoc(doc(adminDb, 'store', 'catalog'), { cats: ['A'], ecat: ['🛒'], colors: ['#ffffff'], chunkCount: 1, productCount: 0, updatedAt: serverTimestamp(), updatedBy: attackerUid }));
  await assertFails(setDoc(doc(adminDb, 'catalog_chunks', 'chunk_0'), { index: 0, items: Array.from({ length: 101 }, () => ({ id: 1 })), updatedAt: serverTimestamp(), updatedBy: adminUid }));
  await assertFails(setDoc(doc(adminDb, 'store', 'x'.repeat(200)), { cats: ['A'], ecat: ['🛒'], colors: ['#ffffff'], chunkCount: 1, productCount: 0, updatedAt: serverTimestamp(), updatedBy: adminUid }));
  await assertFails(setDoc(doc(adminDb, 'store_private', 'admin_auth'), { pin: '3317167', updatedAt: serverTimestamp(), updatedBy: adminUid }));
  await assertFails(getDocs(collection(guestDb, 'product_images')));
  await assertFails(setDoc(doc(attackerDb, 'product_images', 'pimg_1'), { dataUrl: 'data:image/webp;base64,AAAA', mime: 'image/webp', width: 100, height: 100, createdAt: serverTimestamp(), updatedAt: serverTimestamp(), updatedBy: attackerUid }));

  // Orders collection assertions (guest create allowed only with strict initial state; PII reads & admin edits locked to admin)
  const validOrder = {
    orderNumber: '#ESD-1045',
    customerName: 'أحمد محمد',
    phone: '01012345678',
    address: 'المعادي، شارع 9، عمارة 12',
    payMethod: 'cod',
    payLabel: 'الدفع عند الاستلام',
    items: [{ productId: 1, name: 'لبن جهينة', qty: 2, price: 45, returnedQty: 0 }],
    subtotal: 90,
    discountDeduction: 0,
    returnedTotal: 0,
    total: 90,
    status: 0,
    paymentPaid: false,
    notes: '',
    createdAtMs: Date.now(),
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  };
  await assertSucceeds(setDoc(doc(guestDb, 'orders', 'ord_1'), validOrder));
  await assertFails(setDoc(doc(guestDb, 'orders', 'ord_bad'), { ...validOrder, status: 3, paymentPaid: true }));
  await assertFails(setDoc(doc(guestDb, 'orders', 'ord_bad2'), { ...validOrder, total: 1 }));
  await assertFails(getDoc(doc(guestDb, 'orders', 'ord_1')));
  await assertFails(getDocs(collection(attackerDb, 'orders')));
  await assertFails(setDoc(doc(attackerDb, 'orders', 'ord_1'), { ...validOrder, status: 3, updatedBy: attackerUid }));
  await assertSucceeds(getDocs(collection(adminDb, 'orders')));

  // Authorized admin & public guest reads pass
  await assertSucceeds(setDoc(doc(adminDb, 'store', 'catalog'), { cats: ['الألبان'], ecat: ['🧀'], colors: ['#ffc107'], chunkCount: 1, productCount: 1, updatedAt: serverTimestamp(), updatedBy: adminUid }));
  await assertSucceeds(setDoc(doc(adminDb, 'product_images', 'pimg_1'), { dataUrl: 'data:image/webp;base64,UklGRh4AAABXRUJQVlA4TBEAAAAvAAAAAAfQ//73v/+BiOh/AAA=', mime: 'image/webp', width: 100, height: 100, createdAt: serverTimestamp(), updatedAt: serverTimestamp(), updatedBy: adminUid }));
  await assertSucceeds(getDoc(doc(guestDb, 'product_images', 'pimg_1')));
  await assertSucceeds(getDoc(doc(guestDb, 'store', 'catalog')));
  await assertSucceeds(getDoc(doc(adminDb, 'store_private', 'admin_auth')));

  await testEnv.cleanup();
}
