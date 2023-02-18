using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BASEAPI.Models.Dtos;

namespace BASEAPI.Services.EmailService
{
    public interface IEmailService
    {
        void SendEmail(EmailDto request);
    }
}