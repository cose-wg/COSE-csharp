using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CWT
{
    public class CwtException : Exception
    {
        public CwtException(string str) : base(str) { }
    }
}
