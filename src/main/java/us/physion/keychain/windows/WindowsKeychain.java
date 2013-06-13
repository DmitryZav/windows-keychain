package us.physion.keychain.windows;

import com.google.common.base.Objects;
import com.google.common.hash.Hashing;
import org.apache.commons.io.Charsets;
import org.apache.commons.io.FileUtils;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;

import com.sun.jna.platform.win32.Crypt32Util;
import org.apache.commons.io.IOUtils;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Implements a basic Keychain service on Windows using the JNA and the Windows DPAPI
 */
public class WindowsKeychain {

    private final String keychainFolderPath;

    private static Charset UTF8_CHARSET = Charsets.UTF_8;

    public WindowsKeychain(String keychainFolderPath) throws WindowsKeychainException {
        this.keychainFolderPath = checkNotNull(keychainFolderPath);
        try {
            FileUtils.forceMkdir(new File(keychainFolderPath));
        } catch (IOException e) {
            throw new WindowsKeychainException("Unable to create keychain folder", e);
        }
    }


    public void addPassword(String serviceName, String userName, char[] password) throws WindowsKeychainException {
        ByteBuffer passwordByteBuffer = UTF8_CHARSET.encode(CharBuffer.wrap(password));
        byte[] passwordBytes = new byte[passwordByteBuffer.limit()];
        passwordByteBuffer.get(passwordBytes);

        byte[] encryptedPassword = Crypt32Util.cryptProtectData(passwordBytes);

        OutputStream outStream = null;
        try {
            File keyFile = getKeyFile(serviceName, userName);
            outStream = new FileOutputStream(keyFile);
            outStream.write(encryptedPassword);
            zeroArray(encryptedPassword);
        } catch (FileNotFoundException e) {
            throw new WindowsKeychainException("Unable to write key file", e);
        } catch (IOException e) {
            throw new WindowsKeychainException("Unable to write key file", e);
        } finally {
            IOUtils.closeQuietly(outStream);
        }
    }

    private void zeroArray(byte[] array) {
        Arrays.fill(array, (byte)0);
    }

    private String makeKeyFileName(String serviceName, String userName) {
        return Hashing.md5().newHasher().putString(serviceName).putString(userName).hash().toString();
    }

    private File getKeyFile(String serviceName, String userName) {
        return new File(keychainFolderPath, makeKeyFileName(serviceName, userName));
    }

    public char[] getPassword(String serviceName, String userName) throws WindowsKeychainException {
        try {
            byte[] encryptedPassword = FileUtils.readFileToByteArray(getKeyFile(serviceName, userName));
            byte[] clearPassword = Crypt32Util.cryptUnprotectData(encryptedPassword);

            CharBuffer passwordBuffer = UTF8_CHARSET.decode(ByteBuffer.wrap(clearPassword));
            char[] result = new char[passwordBuffer.length()];
            passwordBuffer.get(result);

            return result;
        } catch (IOException e) {
            throw new WindowsKeychainException("Unable to read key file", e);
        }

    }

    public void removePassword(String serviceName, String userName) throws WindowsKeychainException {
        try {
            FileUtils.forceDelete(getKeyFile(serviceName, userName));
        } catch (IOException e) {
            throw new WindowsKeychainException("Unable to delete key file", e);
        }
    }

    public void modifyPassword(String serviceName, String userName, char[] newPassowrd) throws WindowsKeychainException {
        addPassword(serviceName, userName, newPassowrd);
    }
}
