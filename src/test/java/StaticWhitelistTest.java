import chatzis.nikolas.mc.authenticator.IPUtil;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class StaticWhitelistTest {


    private static final Set<String> STATIC_IPS = Set.of(
            "127.0.0.1",
            "196.168.2.1/32",
            "192.168.1.0/24",
            "12.34.254.0/23",
            "20.30.0.0/16",
            "172.30.24.0/25",
            "10.20.192.0/20"
    );

    @Test
    void getSomeIps_checkIfFitsCorrect() throws UnknownHostException {
        assertTrue(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("127.0.0.1")));
        assertFalse(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("1.0.0.1")));

        assertTrue(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("196.168.2.1")));
        assertFalse(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("196.168.2.2")));

        assertTrue(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("192.168.1.1")));
        assertTrue(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("192.168.1.255")));
        assertFalse(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("192.168.2.2")));

        assertTrue(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("12.34.254.2")));
        assertTrue(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("12.34.255.20")));
        assertFalse(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("12.35.0.1")));

        assertTrue(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("20.30.0.0")));
        assertTrue(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("20.30.127.254")));
        assertFalse(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("20.31.0.0")));

        assertTrue(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("172.30.24.2")));
        assertTrue(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("172.30.24.80")));
        assertFalse(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("172.30.23.255")));
        assertFalse(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("172.30.25.2")));
        assertFalse(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("172.31.24.2")));
        assertFalse(IPUtil.isStaticWhitelisted(STATIC_IPS, InetAddress.getByName("173.30.24.2")));
    }

}
