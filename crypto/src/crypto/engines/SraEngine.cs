using System;

namespace Org.BouncyCastle.Crypto.Engines
{
	public class SraEngine
		: RsaEngine
	{
		public override byte[] ProcessBlock(
			byte[]	inBuf,
			int		inOff,
			int		inLen)
		{
			try {
				return base.ProcessBlock(inBuf, inOff, inLen);
			} catch (InvalidOperationException e) {
				throw new InvalidOperationException(e.Message.Replace("RSA", "SRA"));
			} catch (DataLengthException e) {
				throw new DataLengthException(e.Message.Replace("RSA", "SRA"));
			}
		}
	}
}

