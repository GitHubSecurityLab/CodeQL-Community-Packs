using System;
using System.IO;
using System.Text;
using System.Xml;

public class XmlReaderCases
{
    // XML supplied by a caller-provided delegate argument.
    public static void IsParserSafe(Func<string, string> parse) { }

    public void SettingsParseWithUrlResolver()
    {
        IsParserSafe((string xml) =>
        {
            XmlReaderSettings settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Parse;
            settings.XmlResolver = new XmlUrlResolver();
            settings.MaxCharactersFromEntities = 6000;

            using (MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(xml)))
            {
                XmlReader reader = XmlReader.Create(stream, settings); // BAD
                var xmlDocument = new XmlDocument();
                xmlDocument.Load(reader);
                return xmlDocument.InnerText;
            }
        });
    }

    public XmlReader SettingsObjectInitializer(TextReader input)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Parse,
            XmlResolver = new XmlUrlResolver()
        };
        return XmlReader.Create(input, settings); // BAD
    }

    private static XmlReaderSettings MakeSettings()
    {
        var s = new XmlReaderSettings();
        s.DtdProcessing = DtdProcessing.Parse;
        s.XmlResolver = new XmlUrlResolver();
        return s;
    }

    public XmlReader SettingsFromHelper(string path)
    {
        return XmlReader.Create(path, MakeSettings()); // BAD
    }

    public XmlReader SettingsParseOnly(TextReader input)
    {
        // Resolver not set: the default XmlReaderSettings resolver does not resolve external entities.
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        return XmlReader.Create(input, settings); // GOOD
    }

    public XmlReader SettingsResolverOnly(TextReader input)
    {
        // DTDs prohibited by default.
        var settings = new XmlReaderSettings();
        settings.XmlResolver = new XmlUrlResolver();
        return XmlReader.Create(input, settings); // GOOD
    }

    public XmlReader SettingsResolverAlias(TextReader input)
    {
        XmlResolver resolver = new XmlUrlResolver();
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        settings.XmlResolver = resolver;
        return XmlReader.Create(input, settings); // BAD
    }

    public XmlReader SettingsNullResolverAlias(TextReader input)
    {
        XmlResolver resolver = null;
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        settings.XmlResolver = resolver;
        return XmlReader.Create(input, settings); // GOOD
    }

    public XmlReader SettingsSecureResolverAlias(TextReader input)
    {
        XmlResolver resolver = new XmlSecureResolver(new XmlUrlResolver(), "https://example.com/");
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        settings.XmlResolver = resolver;
        return XmlReader.Create(input, settings); // GOOD
    }

    public XmlReader SettingsResolverReset(TextReader input)
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        settings.XmlResolver = new XmlUrlResolver();
        settings.XmlResolver = null;
        return XmlReader.Create(input, settings); // GOOD
    }

    public XmlReader SettingsDtdOverwrite(TextReader input)
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Prohibit;
        settings.DtdProcessing = DtdProcessing.Parse;
        settings.XmlResolver = new XmlUrlResolver();
        return XmlReader.Create(input, settings); // BAD
    }

    public XmlReader SettingsDtdAliasOverwrite(TextReader input)
    {
        var settings = new XmlReaderSettings();
        settings.ProhibitDtd = true;
        settings.DtdProcessing = DtdProcessing.Parse;
        settings.XmlResolver = new XmlUrlResolver();
        return XmlReader.Create(input, settings); // BAD
    }

    public XmlReader WrapExistingReader(XmlReader input)
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        settings.XmlResolver = new XmlUrlResolver();
        return XmlReader.Create(input, settings); // GOOD
    }

    public XmlReader SettingsIgnore(TextReader input)
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Ignore;
        settings.XmlResolver = new XmlUrlResolver();
        return XmlReader.Create(input, settings); // GOOD
    }

    public XmlReader SettingsProhibit(TextReader input)
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Prohibit;
        settings.XmlResolver = new XmlUrlResolver();
        return XmlReader.Create(input, settings); // GOOD
    }

    public XmlReader SettingsNullResolver(TextReader input)
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        settings.XmlResolver = null;
        return XmlReader.Create(input, settings); // GOOD
    }

    public XmlReader DefaultSettings(TextReader input)
    {
        return XmlReader.Create(input); // GOOD
    }
}

public class XmlTextReaderCases
{
    public string ParseWithUrlResolver(string xml)
    {
        XmlTextReader reader = new XmlTextReader(new StringReader(xml)); // BAD
        reader.DtdProcessing = DtdProcessing.Parse;
        reader.XmlResolver = new XmlUrlResolver();
        reader.Read();
        return reader.Name;
    }

    public string ParseWithoutResolver()
    {
        // Constant XML, DTD parsing on, resolver never set: external entities are not resolved.
        string xml = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>";
        XmlTextReader reader = new XmlTextReader(new StringReader(xml)); // GOOD
        reader.DtdProcessing = DtdProcessing.Parse;
        reader.Read();
        return reader.Name;
    }

    public string DefaultDtdWithUrlResolver(string xml)
    {
        // XmlTextReader parses DTDs by default, so only the resolver needs to be opted in.
        XmlTextReader reader = new XmlTextReader(new StringReader(xml)); // BAD
        reader.XmlResolver = new XmlUrlResolver();
        reader.Read();
        return reader.Name;
    }

    public string ProhibitWithUrlResolver(string xml)
    {
        XmlTextReader reader = new XmlTextReader(new StringReader(xml)); // GOOD
        reader.DtdProcessing = DtdProcessing.Prohibit;
        reader.XmlResolver = new XmlUrlResolver();
        reader.Read();
        return reader.Name;
    }

    public string ProhibitDtdWithUrlResolver(string xml)
    {
        XmlTextReader reader = new XmlTextReader(new StringReader(xml)); // GOOD
        reader.ProhibitDtd = true;
        reader.XmlResolver = new XmlUrlResolver();
        reader.Read();
        return reader.Name;
    }

    public string ProhibitDtdAliasOverwrittenWithParse(string xml)
    {
        XmlTextReader reader = new XmlTextReader(new StringReader(xml)); // BAD
        reader.ProhibitDtd = true;
        reader.DtdProcessing = DtdProcessing.Parse;
        reader.XmlResolver = new XmlUrlResolver();
        reader.Read();
        return reader.Name;
    }

    public string ParseWithNullResolver(string xml)
    {
        XmlTextReader reader = new XmlTextReader(new StringReader(xml)); // GOOD
        reader.DtdProcessing = DtdProcessing.Parse;
        reader.XmlResolver = null;
        reader.Read();
        return reader.Name;
    }
}

public class AdditionalCases
{
    public XmlReader SettingsProhibitNoResolver(Stream stream)
    {
        // DTDs stay prohibited and no resolver is assigned.
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Prohibit;
        return XmlReader.Create(stream, settings); // GOOD
    }

    public XmlReader SettingsParseWithUrlResolverStream(Stream stream)
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        settings.XmlResolver = new XmlUrlResolver();
        return XmlReader.Create(stream, settings); // BAD
    }

    public XmlReader SettingsProhibitDtdFalse(Stream stream)
    {
        var settings = new XmlReaderSettings();
        settings.ProhibitDtd = false;
        settings.XmlResolver = new XmlUrlResolver();
        return XmlReader.Create(stream, settings); // BAD
    }

    public XmlReader SettingsParseThenProhibit(Stream stream)
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        settings.XmlResolver = new XmlUrlResolver();
        settings.DtdProcessing = DtdProcessing.Prohibit;
        return XmlReader.Create(stream, settings); // GOOD
    }

    public XmlReader SettingsExclusiveBranches(Stream stream, bool parseDtd)
    {
        // Known limitation: DTD processing and the resolver are set on branches that exclude each other.
        var settings = new XmlReaderSettings();
        if (parseDtd)
            settings.DtdProcessing = DtdProcessing.Parse;
        else
            settings.XmlResolver = new XmlUrlResolver();
        return XmlReader.Create(stream, settings); // GOOD, but reported (known limitation)
    }

    public string TextReaderParseWithoutResolver(string xml)
    {
        // DTD parsing without a resolver: on modern .NET, XmlTextReader resolves no external entity unless a resolver
        // is assigned.
        var textReader = new XmlTextReader(new StringReader(xml)); // GOOD
        textReader.DtdProcessing = DtdProcessing.Parse;
        textReader.Read();
        return textReader.Name;
    }

    public string TextReaderIgnoreWithUrlResolver(string xml)
    {
        var textReader = new XmlTextReader(new StringReader(xml)); // GOOD
        textReader.DtdProcessing = DtdProcessing.Ignore;
        textReader.XmlResolver = new XmlUrlResolver();
        textReader.Read();
        return textReader.Name;
    }

    public void SettingsInLoop(Stream[] streams)
    {
        foreach (var stream in streams)
        {
            var settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Parse;
            settings.XmlResolver = new XmlUrlResolver();
            XmlReader.Create(stream, settings); // BAD
        }
    }

    public void SettingsOverwriteInLoop(Stream[] streams)
    {
        foreach (var stream in streams)
        {
            var settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Prohibit;
            settings.DtdProcessing = DtdProcessing.Parse;
            settings.XmlResolver = new XmlUrlResolver();
            XmlReader.Create(stream, settings); // BAD
        }
    }

    public void TextReaderProhibitAfterParseInLoop(string[] documents)
    {
        foreach (var xml in documents)
        {
            var textReader = new XmlTextReader(new StringReader(xml)); // GOOD
            textReader.XmlResolver = new XmlUrlResolver();
            textReader.DtdProcessing = DtdProcessing.Parse;
            textReader.DtdProcessing = DtdProcessing.Prohibit;
            textReader.Read();
        }
    }
}
