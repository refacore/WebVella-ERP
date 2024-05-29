using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using WebVella.Erp.Api.Models;

namespace WebVella.Erp.Web.Services.Abstractions;

public interface IAuthService
{
    ErpUser Authenticate(string email, string password);

    void Logout();

    ErpUser GetUser(ClaimsPrincipal principal);

    ValueTask<string> GetTokenAsync(string email, string password);

    ValueTask<string> GetNewTokenAsync(string tokenString);

    ValueTask<JwtSecurityToken> GetValidSecurityTokenAsync(string token);
}
