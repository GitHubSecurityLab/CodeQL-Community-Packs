import java.io.IOException;
import java.io.PrintWriter;
import java.util.Base64;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class Base64Encryption extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        HttpSession session = request.getSession();
        String requestBody = request.getReader().readLine();
        session.setAttribute("username", requestBody);
        // Do something with the request body here
        String attr = (String)session.getAttribute("username");
        String responseBody = Base64.getEncoder().encodeToString(attr.getBytes());
        // String responseBody = "Encoded username: " + encodedUsername;
        response.setContentType("text/plain");
        response.setCharacterEncoding("UTF-8");
        response.setStatus(HttpServletResponse.SC_OK);
        PrintWriter out = response.getWriter();
        out.print(responseBody);
        out.flush();
    }
}