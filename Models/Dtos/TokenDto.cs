namespace BASEAPI.Models.Dtos
{
    public class TokenDto
    {
    public string Access_Token { get; set; } = "";
    public string Token_Type { get; set; } = "";
    public DateTime Expires { get; set; }
    }
}