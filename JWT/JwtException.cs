﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Com.AugustCellars.JWT
{
    public class JwtException : Exception
    {
        public JwtException(string text) : base(text) { }
    }
}
