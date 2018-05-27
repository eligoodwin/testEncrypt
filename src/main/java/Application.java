import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Application {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, UnsupportedEncodingException, InvalidKeySpecException {
        AssymEncypt assymEncypt = new AssymEncypt();
        AssymEncypt assymEncypt1 = new AssymEncypt();

        String publicKey = assymEncypt.getPublicKeyString();
        String publicKey2 = assymEncypt1.getPublicKeyString();
        System.out.printf("KEY %s\n", publicKey);
        System.out.printf("KEY2 %s\n", publicKey2);
        String message = "this is java encryption";


        String encryptedMessage = assymEncypt.encryptString(message, assymEncypt.makePublicKeyFromString(assymEncypt1.getPublicKeyString()));
        String encryptedMessage1 = assymEncypt1.encryptString(message, assymEncypt1.makePublicKeyFromString(assymEncypt.getPublicKeyString()));
        System.out.printf("Message 1: %s\n", encryptedMessage);
        System.out.printf("Message 2: %s\n", encryptedMessage1);

        System.out.println(assymEncypt.decryptString(encryptedMessage1));
        System.out.println(assymEncypt1.decryptString(encryptedMessage));


    }

}
