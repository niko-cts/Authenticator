import chatzis.nikolas.mc.authenticator.IPUtil;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class IpConvertTest {


    @Test
    void correctIPToLongCovert() throws UnknownHostException {
        assertEquals(2130706433L, IPUtil.ipToLong(InetAddress.getByName("127.0.0.1")));
        assertEquals(1584572872L, IPUtil.ipToLong(InetAddress.getByName("94.114.169.200")));
        assertEquals(2940928010L, IPUtil.ipToLong(InetAddress.getByName("175.75.0.10")));
    }

}
