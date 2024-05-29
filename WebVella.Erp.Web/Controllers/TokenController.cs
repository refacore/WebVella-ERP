using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Services;

namespace WebVella.Erp.Web.Controllers;

public class TokenController : ApiControllerBase
{
    private readonly LogService logService;

    private readonly AuthService authService;

    public TokenController(LogService logService, AuthService authService)
    {
        this.logService = logService;

        this.authService = authService;
    }

    [AllowAnonymous]
    [Route("api/v3/en_US/auth/jwt/token")]
    [HttpPost]
    public async Task<ActionResult<ResponseModel>> GetJwtToken([FromBody] JwtTokenLoginModel model)
    {
        ResponseModel response = new ResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };

        try
        {
            response.Object = await authService.GetTokenAsync(model.Email, model.Password);
        }
        catch (Exception e)
        {
            logService.Create(Diagnostics.LogType.Error, "GetJwtToken", e);

            response.Success = false;

            response.Message = e.Message + e.StackTrace;
        }

        return Ok(response);
    }

    [AllowAnonymous]
    [Route("api/v3/en_US/auth/jwt/token/refresh")]
    [HttpPost]
    public async Task<ActionResult<ResponseModel>> GetNewJwtToken([FromBody] JwtTokenModel model)
    {
        ResponseModel response = new ResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };
        try
        {
            response.Object = await authService.GetNewTokenAsync(model.Token);
        }
        catch (Exception e)
        {
            new LogService().Create(Diagnostics.LogType.Error, "GetNewJwtToken", e);
            response.Success = false;
            response.Message = e.Message + e.StackTrace;
        }
        return Ok(response);
    }
}
