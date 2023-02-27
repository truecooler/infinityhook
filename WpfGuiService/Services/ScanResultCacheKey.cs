using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WpfGuiService.Services
{
    public class ScanResultCacheKey : IEquatable<ScanResultCacheKey>
    {
        public string FilePath { get; set; }
        public long FileSize { get; set; }
        public DateTime FileLastWriteTime { get; set; }

        public ScanResultCacheKey(string filePath, long fileSize, DateTime fileLastWriteTime)
        {
            FilePath = filePath;
            FileSize = fileSize;
            FileLastWriteTime = fileLastWriteTime;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(FilePath, FileSize, FileLastWriteTime);
        }

        public override bool Equals(object? obj)
        {
            if (obj is ScanResultCacheKey key)
            {
                return Equals(key);
            }

            return false;
        }

        public bool Equals(ScanResultCacheKey? other)
        {
            if (other is null)
            {
                return false;
            }

            if (ReferenceEquals(this, other))
            {
                return true;
            }

            return FilePath == other.FilePath && FileSize == other.FileSize && FileLastWriteTime == other.FileLastWriteTime;
        }
    }
}
