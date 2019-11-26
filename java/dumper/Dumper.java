package dumper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.management.*;
import java.lang.management.*;
import com.sun.management.*;


public class Dumper {
    private String nullValue = null;
    private String stringValue = "ABCDE";
    public boolean booleanValue = true;
    private byte byteValue = 32;
    short shortValue = 22;
    public char charValue = 'И';
    private int intValue = 83;
    private long longValue = 200L;
    private float floatValue = 3.1415f;
    public final double doubleValue = 3.1415926535;
    private Boolean boolValue = false;
    public Integer integerValue = 12345;
    public boolean[] boolArray = {true, false, true, true, false};
    public short[] shortArray = {1, 2, 3, 4, 5};
    public char[] charArray = {'a', 'B', '9', /* WTF? */'\u0888', '!'};
    public int[] intArray = {1, 2, 3, 4, 5};
    public long[] longArray = {1000, 2000, 30000, 400000, 500000000};
    public float[] floatArray = {1000, 2000, 30000, 400000, 500000000};
    public double[] doubleArray = {1000, 2000, 30000, 400000, 500000000};
    public Object obj = new Object();
    private Integer[] hugeArray;

    Dumper(int hugeSize) {
	Integer[] a = new Integer[hugeSize];
	Integer[] b = new Integer[hugeSize];
	for (int i = 0; i < hugeSize; ++i) {
	    a[i] = 2 * i;
	    b[i] = i;
	}
	// One will be kept, another will become a garbage
	this.hugeArray = ((hugeSize & 1) == 0) ? a : b;
    }

    public static void main(String[] v) throws IOException {
	String filePath = "dump.hprof";
	boolean live = false;

	Files.deleteIfExists(Paths.get(filePath));
	// Works with -Xmx4096m
	Dumper dumper = new Dumper(1 << 26);
	
	MBeanServer server = ManagementFactory.getPlatformMBeanServer();
	HotSpotDiagnosticMXBean mxBean = ManagementFactory.newPlatformMXBeanProxy(
            server,
	    "com.sun.management:type=HotSpotDiagnostic",
	    HotSpotDiagnosticMXBean.class
        );
	mxBean.dumpHeap(filePath, live);
    }
}
