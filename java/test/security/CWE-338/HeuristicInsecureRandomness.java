import java.security.SecureRandom;
import java.util.Random;

/**
 * Test cases for the `HeuristicInsecureRandomness` query.
 *
 * Methods prefixed with a security-sensitive name, or that assign the random value to a
 * security-sensitive variable, are expected to be reported. Uses of `java.util.Random`
 * in a non-sensitive context, and any use of `java.security.SecureRandom`, are not.
 */
public class HeuristicInsecureRandomness {

  private static final int AUTHORIZATION_CODE_BOUND = 1_000_000;

  // BAD: java.util.Random is used to generate an authorization code (the issue example).
  // Flagged because the enclosing method name matches a suspicious term ("authoriz").
  public String generateAuthorizationCode(String username) {
    Random predictableRandom = new Random(username.hashCode());
    int code = predictableRandom.nextInt(AUTHORIZATION_CODE_BOUND);
    return String.format("%06d", code);
  }

  // BAD: the random value is assigned to a variable named "token".
  public int nextValue() {
    Random rng = new Random();
    int token = rng.nextInt(1000);
    return token;
  }

  // BAD: the Random instance is stored in a variable named "otpGenerator".
  public int compute() {
    Random otpGenerator = new Random();
    int n = otpGenerator.nextInt(100);
    return n;
  }

  // BAD: Math.random() (which is backed by java.util.Random) produces a value named "secret".
  public double weakSecret() {
    double secret = Math.random();
    return secret;
  }

  // GOOD: SecureRandom is a safe implementation, so it must not be flagged even though the
  // method name and variable name both look security-sensitive.
  public String generatePasswordResetToken() {
    SecureRandom secureRandom = new SecureRandom();
    int token = secureRandom.nextInt(1_000_000);
    return String.format("%06d", token);
  }

  // GOOD: java.util.Random used in a context that is not security-sensitive.
  public int rollDice() {
    Random rng = new Random();
    return rng.nextInt(6);
  }
}
