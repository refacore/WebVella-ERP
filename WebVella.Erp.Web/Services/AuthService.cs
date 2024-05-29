using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using WebVella.Erp.Web.Services.Abstractions;

namespace WebVella.Erp.Web.Services
{
	public class AuthService : IAuthService
	{
		private const double JWT_TOKEN_EXPIRY_DURATION_MINUTES = 1440;

		private const double JWT_TOKEN_FORCE_REFRESH_MINUTES = 120;

		private readonly IHttpContextAccessor httpContextAccessor;

		private readonly SecurityManager securityManager;

		private readonly JwtSecurityTokenHandler tokenHandler;

		public AuthService(
			IHttpContextAccessor httpContextAccessor
			, SecurityManager securityManager
			, JwtSecurityTokenHandler jwtSecurityTokenHandler)
		{
			this.httpContextAccessor = httpContextAccessor;

			this.securityManager = securityManager;

			this.tokenHandler = jwtSecurityTokenHandler;
		}

		public ErpUser Authenticate(string email, string password)
		{
			var user = securityManager.GetUser(email, password);

			if (user == null || !user.Enabled)
			{
				return null;
			}

			var claims = InitClaims(user);

			var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

			var authProperties = new AuthenticationProperties
			{
				AllowRefresh = true,
				ExpiresUtc = DateTimeOffset.UtcNow.AddYears(100),
				IsPersistent = false,
				IssuedUtc = DateTimeOffset.UtcNow,
			};

			httpContextAccessor.HttpContext.SignInAsync(
				  CookieAuthenticationDefaults.AuthenticationScheme
				, new ClaimsPrincipal(claimsIdentity)
				, authProperties);

			return user;
		}

		public void Logout()
		{
			httpContextAccessor.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
		}

		public ErpUser GetUser(ClaimsPrincipal principal)
		{
			if (principal == null
				|| principal.Claims == null
				|| principal.Claims.Count() <= 0)
			{
				return null;
			}

			try
			{
				var claims = principal.Claims;

				Guid userId = new Guid(claims.Single(x => x.Type == ClaimTypes.NameIdentifier.ToString()).Value);

				return securityManager.GetUser(userId);
			}
			catch
			{
				//when exception occur that means schema is changed and cookie is not valid
				return null;
			}
		}

		public async ValueTask<string> GetTokenAsync(string email, string password)
		{
			var user = securityManager.GetUser(email?.Trim()?.ToLowerInvariant(), password?.Trim());

			if (user != null && user.Enabled)
			{
				var (tokenString, token) = await BuildTokenAsync(user);

				return tokenString;
			}

			throw new Exception("Invalid email or password");
		}

		public async ValueTask<string> GetNewTokenAsync(string tokenString)
		{
			JwtSecurityToken jwtToken = await GetValidSecurityTokenAsync(tokenString);

			if (jwtToken == null)
			{
				return null;
			}

			List<Claim> claims = jwtToken.Claims.ToList();

			if (claims.Count == 0)
			{
				return null;
			}

			//validate for active user
			var nameIdentifier = claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier).Value;

			if (!string.IsNullOrWhiteSpace(nameIdentifier))
			{
				var user = securityManager.GetUser(new Guid(nameIdentifier));

				if (user is not null && user.Enabled)
				{
					var (newTokenString, newToken) = await BuildTokenAsync(user);

					return newTokenString;
				}
			}

			return null;
		}

		public async ValueTask<JwtSecurityToken> GetValidSecurityTokenAsync(string token)
		{
			var mySecret = Encoding.UTF8.GetBytes(ErpSettings.JwtKey);

			var mySecurityKey = new SymmetricSecurityKey(mySecret);

			try
			{
				tokenHandler.ValidateToken(
					  token
					, new TokenValidationParameters
					{
						ValidateIssuerSigningKey = true,
						ValidateIssuer = true,
						ValidateAudience = true,
						ValidIssuer = ErpSettings.JwtIssuer,
						ValidAudience = ErpSettings.JwtAudience,
						IssuerSigningKey = mySecurityKey,
					}
					, out SecurityToken validatedToken);

				return await ValueTask.FromResult(validatedToken as JwtSecurityToken);
			}
			catch (Exception)
			{
				return null;
			}
		}

		private async ValueTask<(string, JwtSecurityToken)> BuildTokenAsync(ErpUser user)
		{
			var claims = InitClaims(user);

			var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(ErpSettings.JwtKey));

			var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

			var tokenDescriptor = new JwtSecurityToken(ErpSettings.JwtIssuer, ErpSettings.JwtAudience, claims,
						expires: DateTime.Now.AddMinutes(JWT_TOKEN_EXPIRY_DURATION_MINUTES), signingCredentials: credentials);

			return await ValueTask.FromResult((tokenHandler.WriteToken(tokenDescriptor), tokenDescriptor));
		}

		private static List<Claim> InitClaims(ErpUser user)
		{
			var claims = new List<Claim>
			{
				new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
				new Claim(ClaimTypes.Email, user.Email)
			};

			user.Roles.ForEach(role => claims.Add(new Claim(ClaimTypes.Role.ToString(), role.Name)));

			DateTime tokenRefreshAfterDateTime = DateTime.UtcNow.AddMinutes(JWT_TOKEN_FORCE_REFRESH_MINUTES);

			claims.Add(new Claim(type: "token_refresh_after", value: tokenRefreshAfterDateTime.ToBinary().ToString()));
			return claims;
		}
	}
}
