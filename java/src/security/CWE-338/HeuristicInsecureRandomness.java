import java.security.SecureRandom;
import java.util.Random;

public class HeuristicInsecureRandomness {

  private static final int AUTHORIZATION_CODE_BOUND = 1_000_000;

  // BAD: java.util.Random is used to generate an authorization code. The method name
  // "generateAuthorizationCode" indicates the result is security-sensitive.
  public String generateAuthorizationCode(String username) {
    Random predictableRandom = new Random(username.hashCode());
    int code = predictableRandom.nextInt(AUTHORIZATION_CODE_BOUND);
    return String.format("%06d", code);
  }

  // GOOD: java.security.SecureRandom is a cryptographically strong PRNG, so its output
  // cannot be predicted even though the method name still looks security-sensitive.
  public String generateAuthorizationCodeGood(String username) {
    SecureRandom secureRandom = new SecureRandom();
    int code = secureRandom.nextInt(AUTHORIZATION_CODE_BOUND);
    return String.format("%06d", code);
  }
}
