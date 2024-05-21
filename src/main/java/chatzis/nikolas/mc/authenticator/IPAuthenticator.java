package chatzis.nikolas.mc.authenticator;

import org.bukkit.ChatColor;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerLoginEvent;
import org.bukkit.plugin.java.JavaPlugin;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

/**
 * IPAuthenticator main class.
 * Implements LoginEvent to check if user is in ip range.
 *
 * @author Nikolas Chatzis
 */
public final class IPAuthenticator extends JavaPlugin implements Listener {

    private final Set<String> whitelistedHosts;
    private final Long[] range;

    private boolean addToWhitelist;
    private boolean bypassIfWhitelisted;
    private String kickMessage;
    private String whitelistMessage;

    public IPAuthenticator() {
        this.whitelistedHosts = new HashSet<>();
        this.range = new Long[2];
    }

    @Override
    public void onEnable() {
        saveDefaultConfig();
        FileConfiguration cfg = getConfig();

        this.addToWhitelist = cfg.getBoolean("whitelist.add-to-whitelist");
        this.bypassIfWhitelisted = cfg.getBoolean("whitelist.bypass-if-whitelisted");
        this.kickMessage = cfg.getString("message.kick");
        this.whitelistMessage = cfg.getString("message.whitelisted");

        List<?> list = cfg.getList("ip.statics");
        if (list == null || list.isEmpty()) {
            getLogger().warning("No whitelisted-hostnames found in config.yml");
        } else {
            this.whitelistedHosts.addAll((Set<String>) new HashSet<>(list));
            getLogger().info("Whitelisted IP host addresses: " + String.join(", ", this.whitelistedHosts));
        }

        String ipranges = cfg.getString("ip.range");
        if (ipranges == null) {
            getLogger().warning("No ip-range found in config.yml");
        } else {
            String[] iprange = ipranges.trim().split("-");
            if (iprange.length != 2) {
                getLogger().warning("Invalid ip-range format: " + ipranges);
            } else {
                try {
                    for (int i = 0; i < 2; i++) this.range[i] = IPUtil.ipToLong(InetAddress.getByName(iprange[i]));
                    getLogger().info("IP range " + iprange[0] + " to " + iprange[1]);
                } catch (UnknownHostException ex) {
                    getLogger().warning("Invalid IP address range: " + Arrays.toString(iprange));
                }
            }
        }

        getServer().getPluginManager().registerEvents(this, this);
    }

    @EventHandler
    public void onLogin(PlayerLoginEvent event) {
        if (event.getPlayer().hasPermission("ipauthenticator.bypass") ||
            (bypassIfWhitelisted && event.getPlayer().isWhitelisted()))
            return;

        boolean staticWhitelisted = false;
        try {
            staticWhitelisted = IPUtil.isStaticWhitelisted(whitelistedHosts, event.getRealAddress());
        } catch (NumberFormatException | IllegalStateException e) {
            getLogger().warning("There was an error in your configuration! A static ip was not set correct: " + e.getCause());
        }

        if (staticWhitelisted || isInWhitelistedRange(event.getRealAddress())) {
            if (addToWhitelist) {
                event.getPlayer().setWhitelisted(true);
                getLogger().info("Whitelisted: " + event.getPlayer().getName());
                getServer().getScheduler().runTaskAsynchronously(this, () -> getServer().reloadWhitelist());

                if (!whitelistMessage.isEmpty())
                    getServer().getScheduler().runTaskLater(this, () ->
                            event.getPlayer().sendMessage(ChatColor.translateAlternateColorCodes('&', whitelistMessage.replace("/n", "\n"))), 10L);
            }
        } else {
            event.setKickMessage(ChatColor.translateAlternateColorCodes('&', kickMessage.replace("/n", "\n")));
            event.setResult(PlayerLoginEvent.Result.KICK_WHITELIST);
        }

    }

    private boolean isInWhitelistedRange(InetAddress check) {
        if (range[0] == null || range[1] == null)
            return false;

        long ipToTest = IPUtil.ipToLong(check);
        return ipToTest >= range[0] && ipToTest <= range[1];
    }

}
