package library;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * ProfileStore - LUU HO SO DOC GIA MA HOA AES-128-CBC (dac ta muc 5.1, 5.2).
 *
 * Ho so 100 byte: MSSV(12) | Ho ten(48) | Ngay sinh(4) | Lop(32) | Han the(4)
 * Tren EEPROM: IV(16) + ban ma(112) = 128 byte. 112 = 100 byte ho so + 12 byte dem 0x00 (boi cua 16).
 * Khoa ma hoa la DEK do KeyManager giu trong RAM (co khi da VERIFY_PIN).
 */
public class ProfileStore {

    private static final short PROFILE_PLAIN_LEN = (short) 100;
    private static final short PROFILE_PAD_LEN   = (short) 112;
    private static final short PROFILE_STORE_LEN = (short) 128;
    private static final short IV_LEN            = (short) 16;
    private static final short POLICY_LEN        = (short) 8;
    private static final short COUNTER_LEN       = (short) 4;
    private static final short SET_INFO_LEN      = (short) 84;  // ho ten + ngay sinh + lop
    private static final short SET_INFO_OFFSET   = (short) 12;  // vi tri sau MSSV

    private KeyManager keys;

    // ---------- EEPROM ----------
    private byte[] policy;      // 8 byte chinh sach (so sach, so ngay, phi, nguong no)
    private byte[] counter;     // 4 byte bo dem giao dich (cho nguoi lam muon/tra dung)
    private byte[] profile;     // 128 byte: IV + ban ma

    // ---------- RAM ----------
    private byte[] workBuf;     // 112 byte: noi chua ho so ro khi dang xu ly
    private byte[] cipherBuf;   // 112 byte: ban ma tam truoc khi ghi EEPROM
    private byte[] ivRam;       // 16 byte IV

    private RandomData randomData;
    private AESKey aesKey;
    private Cipher aesCbc;

    public ProfileStore(KeyManager keys) {
        this.keys = keys;
        policy  = new byte[POLICY_LEN];
        counter = new byte[COUNTER_LEN];
        profile = new byte[PROFILE_STORE_LEN];

        workBuf   = JCSystem.makeTransientByteArray(PROFILE_PAD_LEN, JCSystem.CLEAR_ON_DESELECT);
        cipherBuf = JCSystem.makeTransientByteArray(PROFILE_PAD_LEN, JCSystem.CLEAR_ON_DESELECT);
        ivRam     = JCSystem.makeTransientByteArray(IV_LEN,          JCSystem.CLEAR_ON_DESELECT);

        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                                              KeyBuilder.LENGTH_AES_128, false);
        aesCbc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
    }

    // =====================================================================
    //  PHAT HANH THE: luu chinh sach va ho so ma hoa (goi trong giao dich cua ISSUE_CARD)
    //  Luc nay KeyManager.onIssue da sinh DEK vao RAM.
    // =====================================================================
    public void saveIssueData(byte[] buf, short policyOff, short profileOff) {
        Util.arrayCopy(buf, policyOff, policy, (short) 0, POLICY_LEN);
        for (short i = (short) 0; i < COUNTER_LEN; i++) {      // bo dem giao dich bat dau tu 0
            counter[i] = (byte) 0;
        }

        // Dua ho so ro vao workBuf (dem 0x00 cho du 112 byte), roi ma hoa va ghi
        Util.arrayFillNonAtomic(workBuf, (short) 0, PROFILE_PAD_LEN, (byte) 0);
        Util.arrayCopyNonAtomic(buf, profileOff, workBuf, (short) 0, PROFILE_PLAIN_LEN);
        encryptWorkBufAndSave();
        wipeWork();
    }

    // =====================================================================
    //  GET_INFO (INS 0x30): 80 30 00 00 64 -> tra 100 byte ho so
    //  Dieu kien (LibraryApplet kiem tra truoc): the hoat dong va da VERIFY_PIN.
    // =====================================================================
    public void getInfo(APDU apdu) {
        decryptToWorkBuf();
        byte[] buf = apdu.getBuffer();
        Util.arrayCopyNonAtomic(workBuf, (short) 0, buf, (short) 0, PROFILE_PLAIN_LEN);
        wipeWork();
        apdu.setOutgoingAndSend((short) 0, PROFILE_PLAIN_LEN);
    }

    // =====================================================================
    //  SET_INFO (INS 0x31): 80 31 00 00 54 [84 byte: ho ten 48 | ngay sinh 4 | lop 32]
    //  Giu nguyen MSSV (byte 0..11) va han the (byte 96..99). KHONG huy phien.
    // =====================================================================
    public void setInfo(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = PinManager.readData(apdu);
        if (len != SET_INFO_LEN) {
            ISOException.throwIt(PinManager.SW_WRONG_LENGTH);   // 6700
        }

        // 1. Giai ma ho so hien tai ra workBuf
        decryptToWorkBuf();

        // 2. Ghi de 84 byte moi vao vi tri 12..95 (workBuf dang chua ho so ro)
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, workBuf, SET_INFO_OFFSET, SET_INFO_LEN);

        // 3. Ma hoa lai voi IV moi va ghi EEPROM trong mot giao dich
        JCSystem.beginTransaction();
        encryptWorkBufAndSave();
        JCSystem.commitTransaction();

        wipeWork();
    }

    // =====================================================================
    //  HAM NOI BO
    // =====================================================================

    /** Ma hoa workBuf (112 byte, ho so da dem) bang DEK voi IV ngau nhien moi, roi ghi vao profile. */
    private void encryptWorkBufAndSave() {
        randomData.generateData(ivRam, (short) 0, IV_LEN);
        aesKey.setKey(keys.dek(), (short) 0);
        aesCbc.init(aesKey, Cipher.MODE_ENCRYPT, ivRam, (short) 0, IV_LEN);
        aesCbc.doFinal(workBuf, (short) 0, PROFILE_PAD_LEN, cipherBuf, (short) 0);

        // Ghi bang Util.arrayCopy (atomic): trong giao dich, mat dien giua chung thi ve du lieu cu,
        // khong bao gio bi lech IV voi ban ma.
        Util.arrayCopy(ivRam,     (short) 0, profile, (short) 0,      IV_LEN);
        Util.arrayCopy(cipherBuf, (short) 0, profile, IV_LEN,         PROFILE_PAD_LEN);
    }

    /** Giai ma profile (IV o 16 byte dau) bang DEK ra workBuf (112 byte). */
    private void decryptToWorkBuf() {
        aesKey.setKey(keys.dek(), (short) 0);
        aesCbc.init(aesKey, Cipher.MODE_DECRYPT, profile, (short) 0, IV_LEN);
        aesCbc.doFinal(profile, IV_LEN, PROFILE_PAD_LEN, workBuf, (short) 0);
    }

    /** Xoa ho so ro va ban ma tam khoi RAM. */
    private void wipeWork() {
        Util.arrayFillNonAtomic(workBuf,   (short) 0, PROFILE_PAD_LEN, (byte) 0);
        Util.arrayFillNonAtomic(cipherBuf, (short) 0, PROFILE_PAD_LEN, (byte) 0);
    }
}