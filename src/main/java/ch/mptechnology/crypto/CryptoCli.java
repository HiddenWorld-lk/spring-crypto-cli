package ch.mptechnology.crypto;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;

public class CryptoCli {

    /**
     * The default salt as it was used by spring cloud cli to be backwards
     * compatible.
     */
    public static final String HARD_CODED_SALT = "deadbeef";
    public static final String DEFAULT_MODE_OF_AES = "CBC";

    static class BaseCommand {
        @Parameter(names = "--message", description = "The message to be encrypted/decrypted", required = true, order = 1)
        String message;
        @Parameter(names = "--key", description = "The key used to encrypt/decrypt the message", required = true, password = true, order = 2)
        String key;
        @Parameter(names = "--salt", description = "The salt that is used to encrypt/decrypt the message", order = 3)
        String salt = HARD_CODED_SALT;
        @Parameter(names = "--mode", description = "The mode of AES algorithm : CBC(DEFAULT) / GCM", order = 4)
        String mode = DEFAULT_MODE_OF_AES;

    }

    @Parameters(commandDescription = "Encrypts a given message with the given key using AES 256 bit encryption")
    static class CommandEncrypt extends BaseCommand {

    }

    @Parameters(commandDescription = "Decrypts a given message with the given key using AES 256 bit encryption")
    static class CommandDecrypt extends BaseCommand {

    }

    public static void main(String[] args) {
        new CryptoCli().run(args);
    }

    private void run(String[] args) {
        CommandEncrypt encrypt = new CommandEncrypt();
        CommandDecrypt decrypt = new CommandDecrypt();
        JCommander jc = JCommander.newBuilder()
                .addCommand("encrypt", encrypt)
                .addCommand("decrypt", decrypt)
                .build();

        jc.parse(args);

        if (jc.getParsedCommand() == null) {
            printUsageAndExit(jc);
        }
        // 验证加密模式
        BaseCommand command = jc.getParsedCommand().equals("encrypt") ? encrypt : decrypt;
        if (!isValidMode(command.mode)) {
            System.err.println("Invalid mode specified! Mode must be either 'CBC' or 'GCM'");
            printUsageAndExit(jc);
        }
        switch (jc.getParsedCommand()) {
            case "encrypt" ->
                System.out
                        .println(createTextEncryptor(encrypt.key, encrypt.salt, encrypt.mode).encrypt(encrypt.message));
            case "decrypt" ->
                System.out
                        .println(createTextEncryptor(decrypt.key, decrypt.salt, decrypt.mode).decrypt(decrypt.message));
            default -> {
                System.err.println("Invalid mode specified! Mode must be either 'CBC' (default) or 'GCM'");
                printUsageAndExit(jc);
            }
        }
    }

    private static void printUsageAndExit(JCommander jc) {
        jc.usage();
        System.exit(1);
    }

    static TextEncryptor createTextEncryptor(String key, String salt, String mode) {
        return mode.equalsIgnoreCase("GCM")
                ? Encryptors.delux(key, salt)
                : Encryptors.text(key, salt);
    }

    private static boolean isValidMode(String mode) {
        return mode.equalsIgnoreCase(DEFAULT_MODE_OF_AES) || mode.equalsIgnoreCase("GCM");
    }
}
