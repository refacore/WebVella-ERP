﻿using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebVella.Erp.Database;
using WebVella.Erp.Api;
using System;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Web.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Features;

namespace WebVella.Erp.Web.Middleware
{
	public class ErpMiddleware
	{
		private readonly RequestDelegate next;

		private readonly AuthService authService;

		public ErpMiddleware(RequestDelegate next, AuthService authService)
		{
			this.next = next;

			this.authService = authService;
		}

		public async Task Invoke(HttpContext context)
		{
			var syncIOFeature = context.Features.Get<IHttpBodyControlFeature>();
			if (syncIOFeature != null)
				syncIOFeature.AllowSynchronousIO = true;

			IDisposable dbCtx = DbContext.CreateContext(ErpSettings.ConnectionString);
			IDisposable secCtx = null;

			ErpUser user = authService.GetUser(context.User);
			if (user != null)
			{
				secCtx = SecurityContext.OpenScope(user);
			}
			else
			{
				if (context.User.Identity.IsAuthenticated)
				{
					await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
				}
			}

			await next(context);
			await Task.Run(() =>
			{
				if (dbCtx != null)
					dbCtx.Dispose();
				if (secCtx != null)
					secCtx.Dispose();
			});
		}
	}
}
