import java.io.File;
import java.io.FileInputStream;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.XMLReader;

public class XXELocal {
    public static void main(String[] args) throws Exception {
        // Get user input from file
        File file = new File("input.xml");
        FileInputStream inputStream = new FileInputStream(file);
        InputSource inputSource = new InputSource(inputStream);

        // Get XML reader
        XMLReader xmlReader = getXMLReader();

        // Parse XML
        SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();
        SAXParser saxParser = saxParserFactory.newSAXParser();
        saxParser.parse(inputSource, new MyHandler());
    }

    private static XMLReader getXMLReader() throws Exception {
        SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();
        SAXParser saxParser = saxParserFactory.newSAXParser();
        XMLReader xmlReader = saxParser.getXMLReader();
        return xmlReader;
    }

    private static class MyHandler extends DefaultHandler {
        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
            // Handle start element
        }

        @Override
        public void endElement(String uri, String localName, String qName) throws SAXException {
            // Handle end element
        }

        @Override
        public void characters(char[] ch, int start, int length) throws SAXException {
            // Handle character data
        }
    }
}