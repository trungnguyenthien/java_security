package tx.secure;

public interface RandomHelper {
    byte[] nextBytes(int length);
    int nextInt(int bound);
    int nextInt(int origin, int bound);
    long nextLong(long bound);
    long nextLong(long origin, long bound);
    double nextDouble();
    double nextDouble(double origin, double bound);
}
