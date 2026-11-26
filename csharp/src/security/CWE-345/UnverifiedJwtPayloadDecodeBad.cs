public static IList<string> GetRoles(string jwt)
{
    var payload = jwt.Split('.')[1];
    payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
    var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload)); // BAD
    return JObject.Parse(json)["roles"].Values<string>().ToList();
}
