package library;

import javacard.framework.*;

/**
 * PinManager - QUAN LY PIN / PUK.
 *
 * Chuc nang (dac ta FR-01 den FR-03, muc 7.2, 7.6, 7.7):
 *   - Tao PIN/PUK khi phat hanh the (goi tu ISSUE_CARD)
 *   - VERIFY_PIN : kiem tra PIN, sai 3 lan thi khoa
 *   - CHANGE_PIN : doi PIN (can da xac thuc PIN)
 *   - UNBLOCK    : mo khoa bang PUK va dat PIN moi, PUK sai 5 lan thi the bi huy
 *   - GET_STATUS : xem trang thai the, so lan PIN/PUK con lai
 *
 * Dung lop OwnerPIN co san cua Java Card: OwnerPIN tu lo bo dem so lan sai
 * va co "da xac thuc" (co nay tu xoa khi the reset).
 *
 * Cac phan lien quan ma hoa AES do KeyManager xu ly.
 */
public class PinManager {

    // ================= CAU HINH (dac ta muc 3.5) =================
    public static final byte  PIN_TRY_LIMIT = (byte) 3;   // sai PIN toi da 3 lan
    public static final byte  PUK_TRY_LIMIT = (byte) 5;   // sai PUK toi da 5 lan
    public static final short PIN_MIN_LEN   = (short) 4;  // PIN 4..6 chu so
    public static final short PIN_MAX_LEN   = (short) 6;
    public static final short PUK_LEN       = (short) 8;  // PUK dung 8 chu so
    public static final short CARD_ID_LEN   = (short) 8;  // ma the 8 byte

    // ================= TRANG THAI THE (dac ta muc 5.4) =================
    public static final byte STATE_BLANK     = (byte) 0;  // chua phat hanh, chi nhan ISSUE_CARD
    public static final byte STATE_ACTIVE    = (byte) 1;  // dang hoat dong
    public static final byte STATE_PIN_LOCK  = (byte) 2;  // PIN bi khoa (suy ra, KHONG luu)
    public static final byte STATE_DESTROYED = (byte) 3;  // bi huy (PUK het luot)

    // ================= MA TRANG THAI SW (dac ta muc 8.4) =================
    public static final short SW_PIN_BLOCKED  = (short) 0x6983; // PIN bi khoa / the bi huy
    public static final short SW_NOT_VERIFIED = (short) 0x6982; // chua xac thuc PIN
    public static final short SW_BAD_STATE    = (short) 0x6985; // the khong o trang thai cho phep lenh
    public static final short SW_WRONG_TRIES  = (short) 0x63C0; // sai PIN/PUK, 4 bit cuoi = so lan con lai
    public static final short SW_INVALID_DATA = (short) 0x6A80; // du lieu khong hop le (dinh dang, PIN trung...)
    public static final short SW_WRONG_LENGTH = (short) 0x6700; // do dai du lieu sai

    // ================= DU LIEU TRONG EEPROM =================
    private OwnerPIN pin;          // doi tuong PIN (giu gia tri + bo dem sai)
    private OwnerPIN puk;          // doi tuong PUK
    private byte state;            // trang thai the (0, 1, 3)
    private byte[] cardId;         // ma the 8 byte
    private KeyManager keys;       // phan ma hoa

    // ================= KHOI TAO =================
    public PinManager(KeyManager keys) {
        this.keys = keys;
        pin = new OwnerPIN(PIN_TRY_LIMIT, (byte) PIN_MAX_LEN);
        puk = new OwnerPIN(PUK_TRY_LIMIT, (byte) PUK_LEN);
        cardId = new byte[CARD_ID_LEN];
        state = STATE_BLANK;       // the moi chua phat hanh
    }

    // =====================================================================
    //  CAC HAM KIEM TRA DIEU KIEN (nguoi khac cung goi duoc)
    // =====================================================================

    /** The da bi huy thi moi lenh deu tra 6983 (TC-08). Goi o dau process(). */
    public void checkNotDestroyed() {
        if (state == STATE_DESTROYED) {
            ISOException.throwIt(SW_PIN_BLOCKED);
        }
    }

    /** Chi cho phep khi the CHUA phat hanh (dung cho ISSUE_CARD). */
    public void requireBlank() {
        if (state != STATE_BLANK) {
            ISOException.throwIt(SW_BAD_STATE);        // 6985 (TC-09)
        }
    }

    /** Chi cho phep khi the dang hoat dong (chua phat hanh -> 6985, da huy -> 6983). */
    public void requireActive() {
        if (state == STATE_DESTROYED) {
            ISOException.throwIt(SW_PIN_BLOCKED);      // 6983
        }
        if (state != STATE_ACTIVE) {
            ISOException.throwIt(SW_BAD_STATE);        // 6985: chua phat hanh
        }
    }

    /**
     * Yeu cau da xac thuc PIN. Cac lenh can PIN (GET_INFO, BORROW, RETURN...)
     * cua nguoi khac chi can goi ham nay o dau lenh; chua xac thuc thi tra 6982.
     */
    public void requireVerified() {
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_NOT_VERIFIED);
        }
    }

    /**
     * Huy phien xac thuc: xoa co "da xac thuc" va xoa DEK khoi RAM.
     * Goi sau moi giao dich BORROW / RETURN / TOPUP / PAY_FINE (FR-17)
     * va khi chon lai applet.
     */
    public void endSession() {
        pin.reset();               // xoa co da xac thuc cua PIN
        puk.reset();               // xoa co da xac thuc cua PUK
        keys.clearSession();       // xoa DEK dang ro khoi RAM
    }

    // =====================================================================
    //  HAM TIEN ICH
    // =====================================================================

    /**
     * Nhan du lieu cua lenh APDU vao buffer. Tra ve do dai du lieu (Lc).
     * Luu y: voi du lieu lon nhu ISSUE_CARD (131 byte), buffer APDU phai du lon
     * (>= 136 byte). jCardSim va da so the that dap ung duoc; neu the that co buffer nho
     * hon thi can nhan lam nhieu lan bang receiveBytes.
     */
    public static short readData(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = (short) (buf[ISO7816.OFFSET_LC] & 0xFF);
        short read = apdu.setIncomingAndReceive();
        if (read != lc) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        return lc;
    }

    /** Kiem tra mang con co do dai trong [min, max] va toan ky tu '0'..'9' (ASCII 0x30..0x39). */
    public static boolean isDigits(byte[] b, short off, short len, short min, short max) {
        if (len < min || len > max) {
            return false;
        }
        for (short i = 0; i < len; i++) {
            byte c = b[(short) (off + i)];
            if (c < (byte) 0x30 || c > (byte) 0x39) {
                return false;
            }
        }
        return true;
    }

    /**
     * Xu ly khi PIN sai: huy phien, roi nem loi.
     * Het luot thi tra 6983 (khoa), con luot thi tra 63Cx (x = so lan con lai).
     */
    private void failPin() {
        endSession();
        byte tries = pin.getTriesRemaining();
        if (tries == 0) {
            ISOException.throwIt(SW_PIN_BLOCKED);
        }
        ISOException.throwIt((short) (SW_WRONG_TRIES + tries));
    }

    // =====================================================================
    //  PHAT HANH THE: phan PIN / PUK (goi tu ISSUE_CARD trong LibraryApplet)
    //  Ham nay duoc goi BEN TRONG mot giao dich Java Card.
    // =====================================================================
    public void setupFromIssue(byte[] buf, short cardIdOff, short pinOff, short pinLen, short pukOff) {
        Util.arrayCopy(buf, cardIdOff, cardId, (short) 0, CARD_ID_LEN); // luu ma the
        pin.update(buf, pinOff, (byte) pinLen);    // dat PIN, bo dem sai = 3
        puk.update(buf, pukOff, (byte) PUK_LEN);   // dat PUK, bo dem sai = 5
        keys.onIssue(buf, pinOff, pinLen, pukOff, PUK_LEN); // KeyManager: sinh DEK, boc bang PIN/PUK
        state = STATE_ACTIVE;                      // chuyen sang hoat dong (0 -> 1)
    }

    // =====================================================================
    //  VERIFY_PIN (INS 0x20): 80 20 00 00 Lc [PIN]
    //  Dung: 9000 | Sai: 63Cx | Khoa: 6983
    // =====================================================================
    public void verifyPin(APDU apdu) {
        requireActive();
        byte[] buf = apdu.getBuffer();
        short len = readData(apdu);
        short off = ISO7816.OFFSET_CDATA;

        // Sai dinh dang thi bao loi du lieu, KHONG tinh la mot lan nhap sai
        if (!isDigits(buf, off, len, PIN_MIN_LEN, PIN_MAX_LEN)) {
            ISOException.throwIt(SW_INVALID_DATA);
        }

        // PIN da het luot thu thi khong so khop nua
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(SW_PIN_BLOCKED);
        }

        // check(): so khop PIN; neu sai OwnerPIN tu tru 1 lan thu, neu dung thi dat lai bo dem
        if (!pin.check(buf, off, (byte) len)) {
            failPin();
        }

        // PIN dung: nho KeyManager giai boc DEK vao RAM.
        // Neu buoc nay loi (vi du CV sai) thi huy luon phien vua mo.
        try {
            keys.onVerified(buf, off, len);
        } catch (ISOException e) {
            endSession();
            ISOException.throwIt(e.getReason());
        }
    }

    // =====================================================================
    //  CHANGE_PIN (INS 0x24): 80 24 00 00 Lc [lenCu][PIN cu][lenMoi][PIN moi]
    //  Dieu kien: da VERIFY_PIN. PIN moi 4..6 chu so va khac PIN cu.
    // =====================================================================
    public void changePin(APDU apdu) {
        requireActive();
        requireVerified();                         // chua xac thuc -> 6982

        byte[] buf = apdu.getBuffer();
        short len = readData(apdu);
        short off = ISO7816.OFFSET_CDATA;

        // Tach du lieu: [lenCu 1][PIN cu][lenMoi 1][PIN moi]
        short oldLen = (short) (buf[off] & 0xFF);
        short oldOff = (short) (off + 1);
        // Phai con du cho cho byte lenMoi truoc khi doc no
        if ((short) (oldLen + 2) > len) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        short newLen = (short) (buf[(short) (oldOff + oldLen)] & 0xFF);
        short newOff = (short) (oldOff + oldLen + 1);
        if ((short) (oldLen + newLen + 2) != len) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }

        // Kiem tra dinh dang PIN cu va PIN moi (4..6 chu so)
        if (!isDigits(buf, oldOff, oldLen, PIN_MIN_LEN, PIN_MAX_LEN)
                || !isDigits(buf, newOff, newLen, PIN_MIN_LEN, PIN_MAX_LEN)) {
            ISOException.throwIt(SW_INVALID_DATA);
        }

        // PIN moi phai khac PIN cu (TC-06)
        if (oldLen == newLen && Util.arrayCompare(buf, oldOff, buf, newOff, oldLen) == 0) {
            ISOException.throwIt(SW_INVALID_DATA);
        }

        // Kiem tra lai PIN cu; sai thi tinh la mot lan nhap sai (63Cx)
        if (!pin.check(buf, oldOff, (byte) oldLen)) {
            failPin();
        }

        // Doi PIN trong mot giao dich: hoac xong het, hoac khong doi gi (mat dien giua chung).
        // Thu tu quan trong: boc lai DEK truoc, update PIN SAU CUNG,
        // de neu co loi thi PIN cu van con nguyen va khop voi du lieu.
        JCSystem.beginTransaction();
        keys.onPinChanged(buf, newOff, newLen);    // KeyManager: boc lai DEK bang KEK moi
        pin.update(buf, newOff, (byte) newLen);    // dat PIN moi, bo dem sai = 3
        JCSystem.commitTransaction();

        // update() xoa co "da xac thuc". Dac ta quy dinh CHANGE_PIN KHONG huy phien,
        // nen xac thuc lai bang PIN moi (dung chac chan, va DEK van dang o RAM).
        pin.check(buf, newOff, (byte) newLen);
    }

    // =====================================================================
    //  UNBLOCK (INS 0x2C): 80 2C 00 00 Lc [PUK 8][lenMoi 1][PIN moi]
    //  Khong can PIN. PUK sai 5 lan thi the bi huy (trang thai 3).
    // =====================================================================
    public void unblock(APDU apdu) {
        requireActive();

        byte[] buf = apdu.getBuffer();
        short len = readData(apdu);
        short off = ISO7816.OFFSET_CDATA;

        // Tach du lieu: [PUK 8][lenMoi 1][PIN moi]
        if (len < (short) (PUK_LEN + 1)) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }
        short pukOff = off;
        short newLen = (short) (buf[(short) (off + PUK_LEN)] & 0xFF);
        short newOff = (short) (off + PUK_LEN + 1);
        if ((short) (PUK_LEN + 1 + newLen) != len) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }

        // Kiem tra dinh dang: PUK dung 8 chu so, PIN moi 4..6 chu so
        if (!isDigits(buf, pukOff, PUK_LEN, PUK_LEN, PUK_LEN)
                || !isDigits(buf, newOff, newLen, PIN_MIN_LEN, PIN_MAX_LEN)) {
            ISOException.throwIt(SW_INVALID_DATA);
        }

        // So khop PUK. Sai thi giam luot; het luot thi HUY THE (trang thai 3)
        if (!puk.check(buf, pukOff, (byte) PUK_LEN)) {
            byte tries = puk.getTriesRemaining();
            if (tries == 0) {
                state = STATE_DESTROYED;           // ghi trang thai huy truoc khi bao loi
                ISOException.throwIt(SW_PIN_BLOCKED);
            }
            ISOException.throwIt((short) (SW_WRONG_TRIES + tries));
        }

        // PUK dung: dat PIN moi va mo khoa, lam trong mot giao dich.
        // OwnerPIN.update() dong thoi dat lai bo dem sai ve 3 (tuc la mo khoa PIN).
        JCSystem.beginTransaction();
        keys.onUnblock(buf, pukOff, PUK_LEN, newOff, newLen); // KeyManager: giai boc bang PUK, boc lai bang PIN moi
        pin.update(buf, newOff, (byte) newLen);
        JCSystem.commitTransaction();

        endSession();   // sau mo khoa phai VERIFY_PIN lai (xoa co PUK va DEK trong RAM)
    }

    // =====================================================================
    //  GET_STATUS (INS 0x04): 80 04 00 00 0B -> 11 byte
    //  [trang thai 1][PIN con lai 1][PUK con lai 1][ma the 8]
    // =====================================================================
    public void getStatus(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        byte st = state;
        byte pinLeft = PIN_TRY_LIMIT;
        byte pukLeft = PUK_TRY_LIMIT;
        if (state == STATE_ACTIVE) {
            pinLeft = pin.getTriesRemaining();
            pukLeft = puk.getTriesRemaining();
            if (pinLeft == 0) {
                st = STATE_PIN_LOCK;               // PIN het luot -> bao trang thai 2 (khong luu)
            }
        }

        buf[0] = st;
        buf[1] = pinLeft;
        buf[2] = pukLeft;
        Util.arrayCopy(cardId, (short) 0, buf, (short) 3, CARD_ID_LEN);
        apdu.setOutgoingAndSend((short) 0, (short) 11);
    }
}