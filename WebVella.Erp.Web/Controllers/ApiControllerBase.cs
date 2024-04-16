using Microsoft.AspNetCore.Mvc;
using System;
using System.Net;
using WebVella.Erp.Api.Models;
using Microsoft.AspNetCore.Authorization;
using System.Collections.Generic;

namespace WebVella.Erp.Web.Controllers
{
	[Authorize]
	public abstract class ApiControllerBase : Controller
	{
		public ApiControllerBase()
		{
		}

		protected ResponseModel GetFailedResponseModel(string message)
		{
			return new ResponseModel
			{
				Success = false,
				Message = message
			};
		}

		protected ResponseModel GetFailedResponseModel(List<ErrorModel> errors)
		{
			return new ResponseModel
			{
				Success = false,
				Errors = errors
			};
		}

		protected ResponseModel GetSuccessResponseModel(object resultObject)
		{
			return new ResponseModel
			{
				Success = true,
				Object = resultObject
			};
		}

		protected IActionResult DoResponse(BaseResponseModel response)
		{
			if (response.Errors.Count > 0 || !response.Success)
			{
				if (response.StatusCode == HttpStatusCode.OK)
					HttpContext.Response.StatusCode = (int)HttpStatusCode.BadRequest;
				else
					HttpContext.Response.StatusCode = (int)response.StatusCode;
			}

			return Json(response);
		}

		protected IActionResult DoPageNotFoundResponse()
		{
			HttpContext.Response.StatusCode = (int)HttpStatusCode.NotFound;
			return Json(new { });
		}

		protected IActionResult DoItemNotFoundResponse(BaseResponseModel response)
		{
			HttpContext.Response.StatusCode = (int)HttpStatusCode.NotFound;
			return Json(response);
		}

		protected IActionResult DoBadRequestResponse(BaseResponseModel response, string message = null, Exception ex = null)
		{
			response.Timestamp = DateTime.UtcNow;
			response.Success = false;

			if (ErpSettings.DevelopmentMode)
			{
				if (ex != null)
					response.Message = ex.Message + ex.StackTrace;
			}
			else
			{
				if (string.IsNullOrEmpty(message))
					response.Message = "An internal error occurred!";
			}

			HttpContext.Response.StatusCode = (int)HttpStatusCode.BadRequest;
			return Json(response);
		}
	}
}
