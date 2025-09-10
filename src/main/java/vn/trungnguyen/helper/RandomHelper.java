package vn.trungnguyen.helper;

import java.security.SecureRandom;

/**
 * RandomHelper provides a set of utility methods for generating
 * cryptographically secure random values using {@link SecureRandom}.
 *
 * <p>This class is designed to be simple, safe, and easy to maintain.
 * It reuses a single {@code SecureRandom} instance across the application.</p>
 *
 * <h2>Sample usage:</h2>
 * <pre>{@code
 * // Generate 32 random bytes (e.g., for a cryptographic key)
 * byte[] key = RandomHelper.nextBytes(32);
 *
 * // Generate a random integer between 0 (inclusive) and 100 (exclusive)
 * int randInt = RandomHelper.nextInt(100);
 *
 * // Generate a random integer between 50 (inclusive) and 200 (exclusive)
 * int randIntInRange = RandomHelper.nextInt(50, 200);
 *
 * // Generate a random long between 0 (inclusive) and 1_000_000 (exclusive)
 * long randLong = RandomHelper.nextLong(1_000_000L);
 *
 * // Generate a random long between 10 (inclusive) and 1000 (exclusive)
 * long randLongInRange = RandomHelper.nextLong(10, 1000);
 *
 * // Generate a random double between 0.0 and 1.0
 * double randDouble = RandomHelper.nextDouble();
 *
 * // Generate a random double between 5.5 (inclusive) and 10.0 (exclusive)
 * double randDoubleInRange = RandomHelper.nextDouble(5.5, 10.0);
 * }</pre>
 */
public class RandomHelper {
    /** Singleton instance of SecureRandom, seeded automatically by the OS */
    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generates a random byte array of the given length.
     *
     * @param length the number of bytes to generate
     * @return a byte array filled with random values
     */
    public static byte[] nextBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    /**
     * Generates a random integer between 0 (inclusive) and {@code bound} (exclusive).
     *
     * @param bound the upper bound (exclusive). Must be positive.
     * @return a random integer between 0 and bound - 1
     */
    public static int nextInt(int bound) {
        return secureRandom.nextInt(bound);
    }

    /**
     * Generates a random long between 0 (inclusive) and {@code bound} (exclusive).
     *
     * @param bound the upper bound (exclusive). Must be positive.
     * @return a random long between 0 and bound - 1
     */
    public static long nextLong(long bound) {
        return secureRandom.nextLong(bound);
    }

    /**
     * Generates a random long between {@code origin} (inclusive) and {@code bound} (exclusive).
     *
     * @param origin the lower bound (inclusive)
     * @param bound the upper bound (exclusive). Must be greater than origin.
     * @return a random long between origin and bound - 1
     */
    public static long nextLong(long origin, long bound) {
        return secureRandom.nextLong(origin, bound);
    }

    /**
     * Generates a random integer between {@code origin} (inclusive) and {@code bound} (exclusive).
     *
     * @param origin the lower bound (inclusive)
     * @param bound the upper bound (exclusive). Must be greater than origin.
     * @return a random integer between origin and bound - 1
     */
    public static int nextInt(int origin, int bound) {
        return secureRandom.nextInt(origin, bound);
    }

    /**
     * Generates a random double between 0.0 (inclusive) and 1.0 (exclusive).
     *
     * @return a random double between 0.0 and 1.0
     */
    public static double nextDouble() {
        return secureRandom.nextDouble();
    }

    /**
     * Generates a random double between {@code origin} (inclusive) and {@code bound} (exclusive).
     *
     * @param origin the lower bound (inclusive)
     * @param bound the upper bound (exclusive). Must be greater than origin.
     * @return a random double between origin and bound
     */
    public static double nextDouble(double origin, double bound) {
        return secureRandom.nextDouble(origin, bound);
    }
}
