Example:

    WindowsKeychain keychain = WindowsKeychain(keychainFolderPath);
    char[] password = keychain.getPassword("github.com", "physion");
