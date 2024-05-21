package chatzis.nikolas.mc.authenticator;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Set;

public class IPUtil {

    private IPUtil() {
        throw new UnsupportedOperationException("IPUtil cannot be instantiated");
    }

    /**
     * Converts the ip address in a byte array to a long using bit manipulation
     *
     * @param ip - the ip address
     * @return long - representation of ip in a number
     * @since 1.0
     */
    public static long ipToLong(InetAddress ip) {
        byte[] octets = ip.getAddress();
        long result = 0;
        for (byte octet : octets) {
            result <<= 8;
            result |= octet & 0xff;
        }
        return result;
    }


    /**
     * Checks if the given address can be found in the given Set.
     *
     * @param whitelistedHosts Set<String> - all accepted ips in format (0.0.0.0(/xx))
     * @param realAddress      InetAddress - the real address
     * @return boolean - ip is whitelisted
     * @throws NumberFormatException, IllegalStateException - can be thrown if the configuration is wrong
     * @since 1.1
     */
    public static boolean isStaticWhitelisted(Set<String> whitelistedHosts, InetAddress realAddress) throws NumberFormatException, IllegalStateException {
        String clientAddress = realAddress.getHostAddress();
        return whitelistedHosts.stream().anyMatch(ip -> {
            if (!ip.contains("/"))
                return ip.equals(clientAddress);

            String[] split = ip.split("/");

            String subnetIp = split[0];
            int cidrPrefix = Integer.parseInt(split[1]);

            long ipLong = convertIpToLong(clientAddress);
            long subnetLong = convertIpToLong(subnetIp);

            long mask = 0xffffffffL << (32 - cidrPrefix);

            return ((ipLong ^ subnetLong) & mask) == 0;
        });
    }

    private static long convertIpToLong(String ipAddress) throws IllegalStateException {
        String[] parts = ipAddress.split("\\.");
        if (parts.length != 4) {
            throw new IllegalStateException("Invalid IP address format");
        }

        long ipLong = 0;
        for (String s : parts) {
            int part = Integer.parseInt(s);
            if (part < 0 || part > 255) {
                throw new IllegalStateException("Invalid IP address part");
            }
            ipLong = ipLong << 8 | part;
        }

        return ipLong;
    }
}
