using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Threading.Tasks;
using WebVella.Erp.Api;
using WebVella.Erp.Web.Services;

namespace WebVella.Erp.Web.Components
{

	public class UserNavViewComponent : ViewComponent
	{
		protected ErpRequestContext ErpRequestContext { get; set; }

		private readonly AuthService authService;

		public UserNavViewComponent([FromServices] ErpRequestContext coreReqCtx, [FromServices] AuthService authService)
		{
			ErpRequestContext = coreReqCtx;

			this.authService = authService;
		}

		public async Task<IViewComponentResult> InvokeAsync()
		{
			ViewBag.CurrentUser = authService.GetUser(UserClaimsPrincipal);

			ViewBag.PageId = null;

			if (ErpRequestContext.Page != null)
			{
				ViewBag.PageId = ErpRequestContext.Page.Id;
			}

			return await Task.FromResult<IViewComponentResult>(View("UserNav.Default"));
		}
	}
}
