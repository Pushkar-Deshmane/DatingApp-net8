using System;
using API.Model;

namespace API.Interfaces;

public interface ITokenService
{
    string CreateToken(AppUser user);
}
