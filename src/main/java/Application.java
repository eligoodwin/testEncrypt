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
        AssymEncypt assymEncypt1 = new AssymEncypt();
        AssymEncypt assymEncypt2 = new AssymEncypt();

        String publicKey1 = assymEncypt1.getPublicKeyString();
        String publicKey2 = assymEncypt2.getPublicKeyString();
        System.out.printf("KEY %s\n", publicKey1);
        System.out.printf("KEY2 %s\n", publicKey2);
        String message = "this is java encryption";


        String encryptedMessage = assymEncypt1.encryptString(message, assymEncypt1.makePublicKeyFromString(publicKey2));
        String encryptedMessage1 = assymEncypt2.encryptString(message, assymEncypt2.makePublicKeyFromString(publicKey1));
        System.out.printf("Message 1: %s\n", encryptedMessage);
        System.out.printf("Message 2: %s\n", encryptedMessage1);

        System.out.println(assymEncypt1.decryptString(encryptedMessage1));
        System.out.println(assymEncypt2.decryptString(encryptedMessage));


    }

}
