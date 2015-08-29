/*  
    (c) Copyright 2014-2015 Fabio Cuneaz 

    This file is part of Cookie365.

    Cookie365 is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Cookie365 is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Cookie365.  If not, see <http://www.gnu.org/licenses/>.

*/

using System;
using System.Collections.Specialized;
using System.Text.RegularExpressions;

namespace Cookie365
{
    public class Args
    {
        private StringDictionary argDict;
        public Args(string[] args)
        {
            argDict = new StringDictionary();
            Regex regEx = new Regex(@"^-", RegexOptions.IgnoreCase | RegexOptions.Compiled);
            Regex regTrim = new Regex(@"^['""]?(.*?)['""]?$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

            string arg = "";
            string[] chunks;

            foreach (string s in args)
            {
                chunks = regEx.Split(s, 3);

                if (regEx.IsMatch(s))
                {
                    arg = chunks[1];
                    argDict.Add(arg, "true");
                }
                else
                { 
                if (argDict.ContainsKey(arg))
                {
                    chunks[0] = regTrim.Replace(chunks[0], "$1");
                    argDict.Remove(arg);
                    argDict.Add(arg, chunks[0]);
                    arg = "";
                }
                }
          }
        }

        public string this[string arg]
        {
            get
            {
                return (argDict[arg]);
            }
        }
    }
}
