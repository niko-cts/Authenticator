package chatzis.nikolas.mc.authenticator;

import java.net.InetAddress;

public class IPUtil {

    private IPUtil() {
        throw new UnsupportedOperationException("IPUtil cannot be instantiated");
    }

    /**
     * Converts the ip address in a byte array to a long using bit manipulation
     * @param ip - the ip address
     * @return long - representation of ip in a number
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


}
