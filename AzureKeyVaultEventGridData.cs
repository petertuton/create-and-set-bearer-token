using System;

namespace Company.Function
{
    public class AzureKeyVaultEventGridData
    {
        private DateTime _expiry;
        public string Id { get; set; }
        public string VaultName { get; set; }
        public string ObjectType { get; set; }
        public string ObjectName { get; set; }
        public string Version { get; set; }
        public long? NBF { get; set; }
        public long? EXP { 
            set { _expiry = (value != null ? DateTimeOffset.FromUnixTimeSeconds(value.Value).DateTime : DateTime.MaxValue); }
        }
        public DateTime Expiry { get { return _expiry; } }
    }
}
