using Microsoft.Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.CAS
{
    /// <summary>
    ///  
    /// </summary>
    public class CasSignOutHandler
    {
        private readonly CasAuthenticationOptions _options;
        public CasSignOutHandler(CasAuthenticationOptions options)
        {
            _options = options;
        }

        private static List<KeyValuePair<string, DateTime>> _logoutCasClients = new List<KeyValuePair<string, DateTime>>();

        /// <summary>
        /// 处理用户登出
        /// </summary>
        /// <param name="Context"></param>
        public virtual void ApplySignOutRequest(IOwinContext Context)
        {
            //判断是否已经收到cas server的logout消息
            if (Context.Authentication.User != null && _logoutCasClients.Any(p => p.Key == Context.Authentication.User.FindFirst(_options.CasCookieKey).Value))
            {
                Context.Authentication.SignOut();
                Context.Authentication.User = null;
                Context.Response.Cookies.Delete("vi");
                _logoutCasClients.RemoveAll(p => p.Value.AddMinutes(60) > DateTime.Now);
            }
        }

        /// <summary>
        /// 处理接收到CAS服务器推送的注销通知
        /// </summary>
        /// <param name="casCookieValue"></param>
        public virtual void ApplySignOutNotice(string casCookieValue)
        {
            _logoutCasClients.Add(new KeyValuePair<string, DateTime>(casCookieValue, DateTime.Now));
        }
    }
}
