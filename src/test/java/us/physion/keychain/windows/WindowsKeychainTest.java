package us.physion.keychain.windows;


import com.sun.jna.platform.win32.Crypt32Util;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import static junit.framework.Assert.assertNotNull;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class WindowsKeychainTest {

    /**
     * The keychain instance to test.
     */
    private WindowsKeychain keychain;

    @Test
    public void should_round_trip_encryption()
    {
        byte[] clear = new byte[25];
        for (byte i = 0; i < clear.length; i++) {
            clear[i] = i;
        }

        assertThat(Crypt32Util.cryptUnprotectData(Crypt32Util.cryptProtectData(clear)), is(clear));

    }

    /**
     * Try to insert, read and delete a generic password.
     */
    @Test
    public void should_round_trip_password() {
        initKeychain();

        final String serviceName = "testRoundTripGenericPassword_service";
        final String userName = "testRoundTripGenericPassword_username";
        final char[] password = "testRoundTripGenericPassword_password".toCharArray();

        // Add it to the keychain.
        try {
            keychain.addPassword(serviceName, userName, password);
        } catch (WindowsKeychainException e) {
            fail("Failed to add a generic password.");
        }

        // Retrieve it from the keychain
        try {
            char[] pass = keychain.getPassword(serviceName, userName);
            assertThat("Retrieved password did not match.", password, is(pass));
        } catch (WindowsKeychainException e) {
            fail("Failed to retrieve generic password");
        }

        // Delete it from the keychain.
        try {
            keychain.removePassword(serviceName, userName);
        } catch (WindowsKeychainException e) {
            fail("Failed to delete generic password");
        }
    }

    @Test
    public void should_update_password() {
        initKeychain();

        final String serviceName = "testUpdateGenericPassword_service";
        final String userName = "testUpdateGenericPassword_username";
        final char[] password1 = "testUpdateGenericPassword_pw1".toCharArray();
        final char[] password2 = "testUpdateGenericPassword_pw2".toCharArray();

        // Add it to the keychain.
        try {
            keychain.addPassword(serviceName, userName, password1);
        } catch (WindowsKeychainException e) {
            fail("Failed to add a generic password.");
        }

        // Retrieve it from the keychain
        try {
            char[] pass = keychain.getPassword(serviceName, userName);
            assertThat("Retrieved password did not match.", password1, is(pass));
        } catch (WindowsKeychainException e) {
            fail("Failed to retrieve generic password");
        }

        // Modify the existing item in the keychain.
        try {
            keychain.modifyPassword(serviceName, userName, password2);
        } catch (WindowsKeychainException e) {
            fail("Failed to update a generic password.");
        }

        // Retrieve it from the keychain, expect the updated password now
        try {
            char[] pass = keychain.getPassword(serviceName, userName);
            assertThat("Retrieved password did not match.", password2, is(pass));
        } catch (WindowsKeychainException e) {
            fail("Failed to retrieve generic password");
        }

        // Delete it from the keychain.
        try {
            keychain.removePassword(serviceName, userName);
        } catch (WindowsKeychainException e) {
            fail("Failed to delete generic password");
        }

        WindowsKeychainException caught = null;
        try {
            keychain.getPassword(serviceName, userName);
        } catch (WindowsKeychainException ex) {
            caught = ex;
        }

        assertNotNull(caught);
    }

    /**
     * Initialize the keychain for testing.
     */
    private void initKeychain() {
        try {
            if (keychain == null) {
                keychain = new WindowsKeychain(FileUtils.getTempDirectoryPath());
            }
        } catch (WindowsKeychainException e) {
            fail("Failed to initialize keychain");
        }
    }
}
