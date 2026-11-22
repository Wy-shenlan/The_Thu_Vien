package library;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * KeyManager - QUAN LY KHOA AES (dac ta muc 6).
 *
 * Mo hinh khoa:
 *   - DEK : khoa AES-128 ngau nhien, ma hoa du lieu ho so tren the.
 *   - KEK : khoa sinh tu PIN (hoac PUK) qua SHA-256 lap 100 lan cong salt, dung de "boc" DEK.
 *   - The chi luu DEK da boc (wrappedDekPin, wrappedDekPuk). DEK dang ro chi nam trong RAM
 *     khi phien PIN hop le, va bi xoa khi sai PIN, chon lai applet, hoac sau moi giao dich.
 *
 * Cac ham onIssue / onPinChanged / onUnblock chay BEN TRONG mot giao dich Java Card
 * (do PinManager / LibraryApplet mo), nen khong duoc tu goi beginTransaction.
 * Ghi vao EEPROM trong giao dich phai dung Util.arrayCopy (co hoan tac khi huy),
 * KHONG dung arrayCopyNonAtomic (khong duoc hoan tac).
 */
public class KeyManager {

    private static final short KEY_LEN        = (short) 16;  // DEK, KEK: 16 byte
    private static final short SALT_LEN       = (short) 16;  // salt: 16 byte
    private static final short HASH_LEN       = (short) 32;  // SHA-256: 32 byte
    private static final short CV_LEN         = (short) 4;   // gia tri kiem tra khoa: 4 byte
    private static final short KDF_ITERATIONS = (short) 100; // so vong SHA-256 khi sinh KEK

    // ---------- EEPROM (luu lau dai) ----------
    private byte[] saltPin;        // salt dung voi PIN
    private byte[] saltPuk;        // salt dung voi PUK
    private byte[] wrappedDekPin;  // DEK boc bang KEK-PIN (AES-ECB)
    private byte[] wrappedDekPuk;  // DEK boc bang KEK-PUK (AES-ECB)
    private byte[] keyCheckVal;    // 4 byte dau cua SHA-256(DEK), de biet giai boc co dung khong

    // ---------- RAM (tu xoa khi bo chon applet) ----------
    private byte[] dekRam;         // DEK dang ro, chi co khi phien hop le
    private byte[] kekRam;         // KEK tam
    private byte[] hashBufRam;     // vung dem cho SHA-256
    private byte[] wrapTmpRam;     // ket qua boc DEK tam (roi moi chep vao EEPROM)
    private byte[] saltTmpRam;     // salt moi tam (roi moi chep vao EEPROM)

    // ---------- Doi tuong mat ma ----------
    private RandomData randomData;
    private MessageDigest sha256;
    private AESKey aesKey;
    private Cipher aesEcb;

    public KeyManager() {
        saltPin       = new byte[SALT_LEN];
        saltPuk       = new byte[SALT_LEN];
        wrappedDekPin = new byte[KEY_LEN];
        wrappedDekPuk = new byte[KEY_LEN];
        keyCheckVal   = new byte[CV_LEN];

        dekRam     = JCSystem.makeTransientByteArray(KEY_LEN,  JCSystem.CLEAR_ON_DESELECT);
        kekRam     = JCSystem.makeTransientByteArray(KEY_LEN,  JCSystem.CLEAR_ON_DESELECT);
        hashBufRam = JCSystem.makeTransientByteArray(HASH_LEN, JCSystem.CLEAR_ON_DESELECT);
        wrapTmpRam = JCSystem.makeTransientByteArray(KEY_LEN,  JCSystem.CLEAR_ON_DESELECT);
        saltTmpRam = JCSystem.makeTransientByteArray(SALT_LEN, JCSystem.CLEAR_ON_DESELECT);

        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        sha256     = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        aesKey     = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                                                  KeyBuilder.LENGTH_AES_128, false);
        aesEcb     = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
    }

    /** ProfileStore dung DEK (dang o RAM) de ma hoa/giai ma ho so. */
    public byte[] dek() {
        return dekRam;
    }

    // =====================================================================
    //  CAC HAM PinManager GOI
    // =====================================================================

    /** PHAT HANH THE: sinh DEK + salt, boc DEK bang PIN va PUK, tinh CV. DEK o lai RAM de ma hoa ho so. */
    public void onIssue(byte[] buf, short pinOff, short pinLen, short pukOff, short pukLen) {
        randomData.generateData(dekRam, (short) 0, KEY_LEN);        // DEK ngau nhien

        // Boc bang PIN
        randomData.generateData(saltTmpRam, (short) 0, SALT_LEN);
        deriveKek(buf, pinOff, pinLen, saltTmpRam);
        wrapDekInto(wrappedDekPin);
        Util.arrayCopy(saltTmpRam, (short) 0, saltPin, (short) 0, SALT_LEN);

        // Boc bang PUK
        randomData.generateData(saltTmpRam, (short) 0, SALT_LEN);
        deriveKek(buf, pukOff, pukLen, saltTmpRam);
        wrapDekInto(wrappedDekPuk);
        Util.arrayCopy(saltTmpRam, (short) 0, saltPuk, (short) 0, SALT_LEN);

        // CV = 4 byte dau cua SHA-256(DEK)
        sha256.reset();
        sha256.doFinal(dekRam, (short) 0, KEY_LEN, hashBufRam, (short) 0);
        Util.arrayCopy(hashBufRam, (short) 0, keyCheckVal, (short) 0, CV_LEN);
    }

    /** VERIFY_PIN dung: tinh KEK-PIN, giai boc DEK vao RAM, kiem tra CV. */
    public void onVerified(byte[] buf, short pinOff, short pinLen) {
        deriveKek(buf, pinOff, pinLen, saltPin);
        unwrapDek(wrappedDekPin);
        checkCv();
    }

    /** CHANGE_PIN: DEK dang o RAM. Sinh salt moi, tinh KEK tu PIN moi, boc lai DEK. */
    public void onPinChanged(byte[] buf, short newPinOff, short newPinLen) {
        rewrapForPin(buf, newPinOff, newPinLen);
    }

    /** UNBLOCK: PUK da dung. Giai boc DEK bang PUK, roi boc lai bang PIN moi. */
    public void onUnblock(byte[] buf, short pukOff, short pukLen, short newPinOff, short newPinLen) {
        deriveKek(buf, pukOff, pukLen, saltPuk);
        unwrapDek(wrappedDekPuk);
        checkCv();
        rewrapForPin(buf, newPinOff, newPinLen);
    }

    /** Xoa DEK, KEK va cac vung tam khoi RAM. */
    public void clearSession() {
        Util.arrayFillNonAtomic(dekRam,     (short) 0, KEY_LEN,  (byte) 0);
        Util.arrayFillNonAtomic(kekRam,     (short) 0, KEY_LEN,  (byte) 0);
        Util.arrayFillNonAtomic(hashBufRam, (short) 0, HASH_LEN, (byte) 0);
        Util.arrayFillNonAtomic(wrapTmpRam, (short) 0, KEY_LEN,  (byte) 0);
        Util.arrayFillNonAtomic(saltTmpRam, (short) 0, SALT_LEN, (byte) 0);
    }

    // =====================================================================
    //  HAM NOI BO
    // =====================================================================

    /** Sinh salt moi, tinh KEK tu PIN moi, boc dekRam, roi ghi salt + DEK boc vao EEPROM. */
    private void rewrapForPin(byte[] buf, short pinOff, short pinLen) {
        randomData.generateData(saltTmpRam, (short) 0, SALT_LEN);
        deriveKek(buf, pinOff, pinLen, saltTmpRam);
        wrapDekInto(wrappedDekPin);
        Util.arrayCopy(saltTmpRam, (short) 0, saltPin, (short) 0, SALT_LEN);
    }

    /**
     * KDF (dac ta 6.1): H0 = SHA-256(secret || salt); Hi = SHA-256(H(i-1) || salt); KEK = 16 byte dau cua H(k).
     * Ket qua nam trong kekRam.
     */
    private void deriveKek(byte[] secret, short secOff, short secLen, byte[] salt) {
        sha256.reset();
        sha256.update(secret, secOff, secLen);
        sha256.doFinal(salt, (short) 0, SALT_LEN, hashBufRam, (short) 0);

        for (short i = (short) 1; i < KDF_ITERATIONS; i++) {
            sha256.reset();
            sha256.update(hashBufRam, (short) 0, HASH_LEN);
            sha256.doFinal(salt, (short) 0, SALT_LEN, hashBufRam, (short) 0);
        }
        Util.arrayCopyNonAtomic(hashBufRam, (short) 0, kekRam, (short) 0, KEY_LEN); // kekRam la RAM
    }

    /** Boc dekRam bang kekRam (AES-ECB), ket qua chep vao mang EEPROM dest (atomic). */
    private void wrapDekInto(byte[] dest) {
        aesKey.setKey(kekRam, (short) 0);
        aesEcb.init(aesKey, Cipher.MODE_ENCRYPT);
        aesEcb.doFinal(dekRam, (short) 0, KEY_LEN, wrapTmpRam, (short) 0);
        Util.arrayCopy(wrapTmpRam, (short) 0, dest, (short) 0, KEY_LEN);
    }

    /** Giai boc wrapped bang kekRam (AES-ECB) ra dekRam. */
    private void unwrapDek(byte[] wrapped) {
        aesKey.setKey(kekRam, (short) 0);
        aesEcb.init(aesKey, Cipher.MODE_DECRYPT);
        aesEcb.doFinal(wrapped, (short) 0, KEY_LEN, dekRam, (short) 0);
    }

    /** So 4 byte dau SHA-256(dekRam) voi CV da luu; sai thi xoa phien va bao 6F00. */
    private void checkCv() {
        sha256.reset();
        sha256.doFinal(dekRam, (short) 0, KEY_LEN, hashBufRam, (short) 0);
        if (Util.arrayCompare(hashBufRam, (short) 0, keyCheckVal, (short) 0, CV_LEN) != (byte) 0) {
            clearSession();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }
}