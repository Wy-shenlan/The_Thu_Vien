package library;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * PhotoStore - LUU ANH THE MA HOA AES-128-CBC (dac ta FR-09, muc 5.1, 7.8, 8.2).
 *
 * - Anh JPEG toi da 3072 byte. Du lieu goc = 2 byte do dai anh (big-endian) + noi dung anh.
 * - Truyen theo khoi 240 byte (15 khoi AES), chi so khoi 0..12 nam trong P1 P2.
 *   Khoi 0 bat dau bang 2 byte do dai anh.
 * - Tren EEPROM: IV (16 byte) + ban ma (3088 byte) = 3104 byte.
 * - Khoa ma hoa la DEK do KeyManager giu trong RAM (co khi da VERIFY_PIN).
 *
 * Mach CBC cua cac khoi noi tiep nhau: khoi ke tiep dung 16 byte ma cuoi cua khoi truoc lam IV.
 * Vi 240 chia het cho 16 nen moi khoi bat dau dung o ranh gioi khoi AES, nho vay doc/ghi tung khoi
 * duoc ma khong can giu trang thai CBC.
 *
 * Anh chi co hieu luc khi khoi cuoi da ghi xong. Bat dau ghi lai (khoi 0) thi anh cu mat hieu luc;
 * ghi do dang (mat dien, reset, bo chon applet) thi the coi nhu chua co anh va phai ghi lai tu khoi 0.
 */
public class PhotoStore {

    private static final short BLOCK_LEN       = (short) 240;   // moi khoi truyen toi da 240 byte
    private static final short MAX_BLOCK_INDEX = (short) 12;    // chi so khoi 0..12
    private static final short MAX_IMAGE_LEN   = (short) 3072;  // anh toi da 3 KB
    private static final short IV_LEN          = (short) 16;
    private static final short STORE_LEN       = (short) 3104;  // IV 16 + ban ma 3088

    // Ma loi rieng cua dac ta (muc 8.4)
    private static final short SW_IMAGE_TOO_BIG = (short) 0x6A84; // anh qua lon
    private static final short SW_WRONG_P1P2    = (short) 0x6A86; // chi so khoi sai
    private static final short SW_NOT_FOUND     = (short) 0x6A88; // chua co anh

    private KeyManager keys;

    // ---------- EEPROM ----------
    private byte[] photo;          // IV + ban ma
    private boolean photoValid;    // true khi da ghi xong khoi cuoi

    // ---------- RAM ----------
    private byte[] workBuf;        // 240 byte: du lieu ro cua mot khoi
    private byte[] cipherBuf;      // 240 byte: ban ma tam cua mot khoi
    private byte[] ivRam;          // 16 byte IV
    private short[] upload;        // [0] = khoi ke tiep can ghi, [1] = tong do dai du lieu (2 + do dai anh); 0 = khong co dot ghi nao

    private AESKey aesKey;
    private Cipher aesCbc;
    private RandomData randomData;

    public PhotoStore(KeyManager keys) {
        this.keys = keys;
        photo = new byte[STORE_LEN];
        photoValid = false;

        workBuf   = JCSystem.makeTransientByteArray(BLOCK_LEN, JCSystem.CLEAR_ON_DESELECT);
        cipherBuf = JCSystem.makeTransientByteArray(BLOCK_LEN, JCSystem.CLEAR_ON_DESELECT);
        ivRam     = JCSystem.makeTransientByteArray(IV_LEN,    JCSystem.CLEAR_ON_DESELECT);
        upload    = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_DESELECT);

        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                                              KeyBuilder.LENGTH_AES_128, false);
        aesCbc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }

    // =====================================================================
    //  SET_PHOTO (INS 0x33): 80 33 P1 P2 Lc [du lieu khoi]
    //  P1 P2 = chi so khoi (0..12). Khoi 0 bat dau bang 2 byte do dai anh.
    //  Dieu kien (LibraryApplet kiem tra truoc): the hoat dong va da VERIFY_PIN. KHONG huy phien.
    //  Phai gui lan luot khoi 0, 1, 2, ... den het.
    // =====================================================================
    public void setPhoto(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short idx = blockIndex(buf);                       // sai chi so -> 6A86
        short len = PinManager.readData(apdu);
        short off = ISO7816.OFFSET_CDATA;
        if (len < (short) 1 || len > BLOCK_LEN) {
            ISOException.throwIt(PinManager.SW_WRONG_LENGTH);        // 6700
        }

        short total;                                       // tong do dai du lieu = 2 + do dai anh
        if (idx == (short) 0) {
            // Khoi dau: doc do dai anh
            if (len < (short) 2) {
                ISOException.throwIt(PinManager.SW_WRONG_LENGTH);    // 6700
            }
            short imgLen = Util.getShort(buf, off);
            if (imgLen < (short) 0 || imgLen > MAX_IMAGE_LEN) {
                ISOException.throwIt(SW_IMAGE_TOO_BIG);              // 6A84
            }
            if (imgLen == (short) 0) {
                ISOException.throwIt(PinManager.SW_INVALID_DATA);    // 6A80
            }
            total = (short) (imgLen + 2);
        } else {
            // Khoi tiep theo: phai dang co dot ghi dang do va dung thu tu
            total = upload[1];
            if (total == (short) 0 || idx != upload[0]) {
                ISOException.throwIt(PinManager.SW_BAD_STATE);       // 6985
            }
        }

        // Do dai du lieu cua khoi nay phai dung: 240, tru khoi cuoi la phan con lai
        short start = (short) (idx * BLOCK_LEN);
        short expected = (short) (total - start);
        if (expected > BLOCK_LEN) {
            expected = BLOCK_LEN;
        }
        if (len != expected) {
            ISOException.throwIt(PinManager.SW_WRONG_LENGTH);        // 6700
        }

        // IV: khoi 0 dung IV ngau nhien moi; khoi sau dung 16 byte ma cuoi cua khoi truoc
        if (idx == (short) 0) {
            randomData.generateData(ivRam, (short) 0, IV_LEN);
        } else {
            Util.arrayCopyNonAtomic(photo, start, ivRam, (short) 0, IV_LEN);   // photo[IV_LEN + start - 16] = photo[start]
        }

        // Dem 0x00 cho du boi so cua 16 roi ma hoa
        short padded = roundUp16(len);
        Util.arrayFillNonAtomic(workBuf, (short) 0, BLOCK_LEN, (byte) 0);
        Util.arrayCopyNonAtomic(buf, off, workBuf, (short) 0, len);
        aesKey.setKey(keys.dek(), (short) 0);
        aesCbc.init(aesKey, Cipher.MODE_ENCRYPT, ivRam, (short) 0, IV_LEN);
        aesCbc.doFinal(workBuf, (short) 0, padded, cipherBuf, (short) 0);

        // Ghi EEPROM trong mot giao dich (Util.arrayCopy de duoc hoan tac khi huy)
        boolean last = (short) (start + len) == total;
        JCSystem.beginTransaction();
        if (idx == (short) 0) {
            photoValid = false;                            // bat dau ghi lai: anh cu mat hieu luc
            Util.arrayCopy(ivRam, (short) 0, photo, (short) 0, IV_LEN);
        }
        Util.arrayCopy(cipherBuf, (short) 0, photo, (short) (IV_LEN + start), padded);
        if (last) {
            photoValid = true;                             // khoi cuoi xong: anh co hieu luc
        }
        JCSystem.commitTransaction();

        // Cap nhat trang thai dot ghi (RAM)
        if (last) {
            upload[0] = (short) 0;
            upload[1] = (short) 0;
        } else {
            upload[0] = (short) (idx + 1);
            upload[1] = total;
        }
        wipe();
    }

    // =====================================================================
    //  GET_PHOTO (INS 0x32): 80 32 P1 P2 Le
    //  P1 P2 = chi so khoi (0..12). Tra toi da 240 byte cua (2 byte do dai + anh).
    //  Khoi 0 cho biet do dai anh, tu do biet con bao nhieu khoi. Dieu kien: the hoat dong, da VERIFY_PIN.
    // =====================================================================
    public void getPhoto(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short idx = blockIndex(buf);                       // sai chi so -> 6A86
        if (!photoValid) {
            ISOException.throwIt(SW_NOT_FOUND);                      // 6A88: chua co anh
        }

        short total = (short) (readImageLength() + 2);
        short start = (short) (idx * BLOCK_LEN);
        if (start >= total) {
            ISOException.throwIt(SW_WRONG_P1P2);                     // chi so khoi vuot qua cuoi anh
        }
        short outLen = (short) (total - start);
        if (outLen > BLOCK_LEN) {
            outLen = BLOCK_LEN;
        }
        short padded = roundUp16(outLen);

        // IV: khoi 0 dung IV da luu (photo[0..15]); khoi sau dung 16 byte ma cuoi cua khoi truoc (photo[start])
        short ivOff = (idx == (short) 0) ? (short) 0 : start;
        aesKey.setKey(keys.dek(), (short) 0);
        aesCbc.init(aesKey, Cipher.MODE_DECRYPT, photo, ivOff, IV_LEN);
        aesCbc.doFinal(photo, (short) (IV_LEN + start), padded, workBuf, (short) 0);

        Util.arrayCopyNonAtomic(workBuf, (short) 0, buf, (short) 0, outLen);
        wipe();
        apdu.setOutgoingAndSend((short) 0, outLen);
    }

    // =====================================================================
    //  HAM NOI BO
    // =====================================================================

    /** Doc chi so khoi tu P1 P2 (big-endian); ngoai 0..12 thi tra 6A86. */
    private short blockIndex(byte[] buf) {
        short idx = Util.getShort(buf, ISO7816.OFFSET_P1);
        if (idx < (short) 0 || idx > MAX_BLOCK_INDEX) {
            ISOException.throwIt(SW_WRONG_P1P2);
        }
        return idx;
    }

    /** Giai ma 16 byte dau cua anh de lay do dai anh (2 byte dau cua du lieu goc). */
    private short readImageLength() {
        aesKey.setKey(keys.dek(), (short) 0);
        aesCbc.init(aesKey, Cipher.MODE_DECRYPT, photo, (short) 0, IV_LEN);
        aesCbc.doFinal(photo, IV_LEN, IV_LEN, workBuf, (short) 0);
        short imgLen = Util.getShort(workBuf, (short) 0);
        if (imgLen <= (short) 0 || imgLen > MAX_IMAGE_LEN) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);                // du lieu anh hong
        }
        return imgLen;
    }

    /** Lam tron len boi so cua 16. */
    private short roundUp16(short n) {
        return (short) (((short) (n + 15) / 16) * 16);
    }

    /** Xoa du lieu ro va ban ma tam khoi RAM. */
    private void wipe() {
        Util.arrayFillNonAtomic(workBuf,   (short) 0, BLOCK_LEN, (byte) 0);
        Util.arrayFillNonAtomic(cipherBuf, (short) 0, BLOCK_LEN, (byte) 0);
    }
}