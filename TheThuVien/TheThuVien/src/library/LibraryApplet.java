package library;

import javacard.framework.*;

/**
 * LibraryApplet - applet chinh cua the thu vien thong minh.
 *
 * File nay chi lam 3 viec: cai dat (install), nhan lenh APDU roi chia cho dung noi xu ly (process),
 * va xu ly ISSUE_CARD (phat hanh the). Moi nguoi them lenh cua minh vao switch trong process().
 *
 * PIN/PUK nam trong PinManager. Khoa AES nam trong KeyManager.
 * Ho so ma hoa (GET_INFO/SET_INFO) nam trong ProfileStore.
 *
 * Quy uoc chung (dac ta muc 8.1): CLA = 0x80; so nhieu byte theo big-endian.
 */
public class LibraryApplet extends Applet {

    // ================= MA LENH (theo bang o dac ta muc 8.2) =================
    public static final byte CLA_LIB = (byte) 0x80;     // CLA dung cho moi lenh

    public static final byte INS_ISSUE_CARD = (byte) 0x01; // phat hanh the
    public static final byte INS_GET_STATUS = (byte) 0x04; // xem trang thai the
    public static final byte INS_VERIFY_PIN = (byte) 0x20; // xac thuc PIN
    public static final byte INS_CHANGE_PIN = (byte) 0x24; // doi PIN
    public static final byte INS_UNBLOCK    = (byte) 0x2C; // mo khoa bang PUK
    public static final byte INS_GET_INFO   = (byte) 0x30; // xem ho so
    public static final byte INS_SET_INFO   = (byte) 0x31; // cap nhat ho so
    public static final byte INS_GET_PHOTO  = (byte) 0x32; // doc anh (tung khoi 240 byte)
    public static final byte INS_SET_PHOTO  = (byte) 0x33; // ghi anh (tung khoi 240 byte)
    // TODO (ca nhom): RENEW_CARD 0x34, BORROW 0x40, RETURN 0x42, ... them vao day.

    // ================= BO CUC DU LIEU CUA ISSUE_CARD (tong 131 byte) =================
    // [ma the 8][do dai PIN 1][PIN 6, dem 0x00][PUK 8][chinh sach 8][ho so 100]
    private static final short ISS_CARD_ID = (short) 0;
    private static final short ISS_PIN_LEN = (short) 8;
    private static final short ISS_PIN     = (short) 9;
    private static final short ISS_PUK     = (short) 15;
    private static final short ISS_POLICY  = (short) 23;
    private static final short ISS_PROFILE = (short) 31;
    private static final short ISS_LENGTH  = (short) 131;

    private KeyManager keyManager;     // khoa AES
    private PinManager pinManager;     // PIN/PUK
    private ProfileStore profileStore; // ho so ma hoa
    private PhotoStore photoStore;     // anh the ma hoa

    // ================= KHOI TAO =================
    private LibraryApplet() {
        keyManager = new KeyManager();
        pinManager = new PinManager(keyManager);
        profileStore = new ProfileStore(keyManager);
        photoStore = new PhotoStore(keyManager);
    }

    /** JCRE goi ham nay khi cai applet: tao doi tuong va dang ky AID. */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new LibraryApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    /** Khi applet bi bo chon (hoac chon lai): xoa phien PIN va DEK trong RAM. */
    public void deselect() {
        pinManager.endSession();
    }

    // ================= NHAN LENH APDU =================
    public void process(APDU apdu) {
        // Lenh SELECT applet: khong can xu ly them
        if (selectingApplet()) {
            return;
        }

        byte[] buf = apdu.getBuffer();

        // CLA phai dung 0x80
        if (buf[ISO7816.OFFSET_CLA] != CLA_LIB) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);     // 6E00
        }

        // The da bi huy thi moi lenh deu tra 6983
        pinManager.checkNotDestroyed();

        // Chia lenh theo INS
        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_ISSUE_CARD: issueCard(apdu);          break;
            case INS_GET_STATUS: pinManager.getStatus(apdu); break;
            case INS_VERIFY_PIN: pinManager.verifyPin(apdu); break;
            case INS_CHANGE_PIN: pinManager.changePin(apdu); break;
            case INS_UNBLOCK:    pinManager.unblock(apdu);   break;
            case INS_GET_INFO:
                pinManager.requireActive();     // chua phat hanh -> 6985
                pinManager.requireVerified();   // chua xac thuc PIN -> 6982
                profileStore.getInfo(apdu);
                break;
            case INS_SET_INFO:
                pinManager.requireActive();
                pinManager.requireVerified();
                profileStore.setInfo(apdu);
                break;
            case INS_GET_PHOTO:
                pinManager.requireActive();
                pinManager.requireVerified();
                photoStore.getPhoto(apdu);
                break;
            case INS_SET_PHOTO:
                pinManager.requireActive();
                pinManager.requireVerified();
                photoStore.setPhoto(apdu);      // khong huy phien (FR-17 khong ap dung)
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); // 6D00
        }
    }

    // =====================================================================
    //  ISSUE_CARD (INS 0x01): 80 01 00 00 83 [131 byte du lieu]
    //  Chi lam duoc mot lan (trang thai 0 -> 1). The da phat hanh thi tra 6985.
    // =====================================================================
    private void issueCard(APDU apdu) {
        pinManager.requireBlank();                  // khong phai the trang -> 6985

        byte[] buf = apdu.getBuffer();
        short len = PinManager.readData(apdu);
        if (len != ISS_LENGTH) {
            ISOException.throwIt(PinManager.SW_WRONG_LENGTH);       // 6700
        }

        short base   = ISO7816.OFFSET_CDATA;
        short pinLen = (short) (buf[(short) (base + ISS_PIN_LEN)] & 0xFF);
        short pinOff = (short) (base + ISS_PIN);
        short pukOff = (short) (base + ISS_PUK);

        // PIN: 4..6 chu so; PUK: dung 8 chu so
        if (!PinManager.isDigits(buf, pinOff, pinLen,
                                 PinManager.PIN_MIN_LEN, PinManager.PIN_MAX_LEN)
                || !PinManager.isDigits(buf, pukOff, PinManager.PUK_LEN,
                                        PinManager.PUK_LEN, PinManager.PUK_LEN)) {
            ISOException.throwIt(PinManager.SW_INVALID_DATA);       // 6A80
        }

        // Ghi moi thu trong MOT giao dich: loi giua chung thi the van la the trang.
        JCSystem.beginTransaction();

        // ma the, PIN, PUK, roi chuyen trang thai sang hoat dong
        pinManager.setupFromIssue(buf, (short) (base + ISS_CARD_ID), pinOff, pinLen, pukOff);

        // luu chinh sach (8 byte) va ho so 100 byte ma hoa bang DEK vua sinh.
        //         Khong duoc goi beginTransaction trong ham nay vi dang trong giao dich.
        profileStore.saveIssueData(buf, (short) (base + ISS_POLICY), (short) (base + ISS_PROFILE));

        JCSystem.commitTransaction();

        // Xoa DEK khoi RAM sau khi phat hanh: lan dung sau bat buoc VERIFY_PIN
        pinManager.endSession();
    }
}