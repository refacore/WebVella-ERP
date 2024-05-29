using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.Circuits;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Database;
using WebVella.Erp.Web.Services;

namespace WebVella.Erp.Web.Middleware
{
	public class SecuritityCircuitHandler : CircuitHandler
	{
		private readonly AuthenticationStateProvider authStateProvider = null;

		private readonly AuthService authService;

		private Dictionary<Circuit, Tuple<IDisposable, IDisposable>> contexts = new Dictionary<Circuit, Tuple<IDisposable, IDisposable>>();

		public SecuritityCircuitHandler(AuthenticationStateProvider authStateProvider, AuthService authService)
		{
			this.authStateProvider = authStateProvider;

			this.authService = authService;
		}

		public override Task OnConnectionUpAsync(Circuit circuit, CancellationToken cancellationToken)
		{
			IDisposable dbCtx = DbContext.CreateContext(ErpSettings.ConnectionString);
			ErpUser user = authService.GetUser(authStateProvider.GetAuthenticationStateAsync().Result.User);
			IDisposable secCtx = user != null ? WebVella.Erp.Api.SecurityContext.OpenScope(user) : null;
			contexts.Add(circuit, new Tuple<IDisposable, IDisposable>(dbCtx, secCtx));
			return Task.CompletedTask;
		}

		public override Task OnConnectionDownAsync(Circuit circuit, CancellationToken cancellationToken)
		{
			if (contexts.ContainsKey(circuit))
			{
				Tuple<IDisposable, IDisposable> tuple = contexts[circuit];
				tuple.Item1.Dispose();
				tuple.Item2.Dispose();
				contexts.Remove(circuit);
			}
			return Task.CompletedTask;
		}

		public int ConnectedCircuits => contexts.Count;
	}
}
