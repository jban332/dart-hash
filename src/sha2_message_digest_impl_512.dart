/*
Copyright 2012 Jban332 <jban332@gmail.com>.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

class _Sha2MessageDigestImpl512 extends _Sha2MessageDigestImplBase {
  
  // Constants
  static final List<int> _constants = const [
                                 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
                                 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
                                 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                                 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
                                 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                                 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                                 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
                                 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
                                 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                                 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                                 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
                                 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                                 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
                                 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
                                 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                                 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
                                 0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
                                 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                                 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
                                 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817];
  static final int _BLOCK_LENGTH_IN_BYTES = 128;
  static final int _ROUNDS = 80;
  static final int _INTEGER_SIZE_IN_BYTES = 8;
  static final int _INTEGER_SIZE_IN_BITS = 64;
  static final int _INTEGER_MASK = 0xFFFFFFFFFFFFFFFF;
  
  int get blockLength() => _BLOCK_LENGTH_IN_BYTES;
  int get hashLength() => 64;
  
  // Initial values for SHA2-512.
  // SHA2-384 has different initial values.
  static final List<int> _initialValues512 = const [0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                                                    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                                                    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                                                    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179];
  final List<int> _initialValues = _initialValues512;
  
  // Creates a result array.
  // SHA2-384 overrides this.
  List<int> _createDigestByteList(List<int> integers) {
    List<int> array = new List(8*integers.length);
    for (int i=0; i<integers.length; i++) {
      int h = integers[i];
      int bi = 8*i;
      array[bi] = 0xFF & (h >> 56);
      array[bi+1] = 0xFF & (h >> 48);
      array[bi+2] = 0xFF & (h >> 40);
      array[bi+3] = 0xFF & (h >> 32);
      array[bi+4] = 0xFF & (h >> 24);
      array[bi+5] = 0xFF & (h >> 16);
      array[bi+6] = 0xFF & (h >> 8);
      array[bi+7] = 0xFF & (h >> 0);
    }
    return array;
  }
  
  static int _rightRotate64(int value, int bits) => _IntUtils.rightRotate64(value, bits);
  
  List<int> _updateWithChunk(List<int> chunkBytes, int chunkOffset, int chunkLength, bool isLastChunk) {
    if (chunkLength==0 && !isLastChunk) return null;
    _messageLength += chunkLength*8;
    
    // If there are bytes in the buffer
    if (_buffer.length > 0 && chunkBytes !== _buffer) {
      int d = Math.min(chunkLength, _BLOCK_LENGTH_IN_BYTES - _buffer.length);
      _buffer.addAll(chunkBytes.getRange(chunkOffset, d));
      chunkOffset += d;
      chunkLength -= d;
      if (_buffer.length == _BLOCK_LENGTH_IN_BYTES) {
        _messageLength -= _buffer.length*8;
        _updateWithChunk(_buffer, 0, _buffer.length, false);
        _buffer.clear();
      }
      else {
        // Continue only if this is the last block
        if (!isLastChunk) return null;
        chunkBytes = _buffer;
        chunkOffset = 0;
        chunkLength = _buffer.length;
      }
    }
    
    // Digest of all previous blocks
    int h0 = _h0;
    int h1 = _h1;
    int h2 = _h2;
    int h3 = _h3;
    int h4 = _h4;
    int h5 = _h5;
    int h6 = _h6;
    int h7 = _h7;
    
    // A temporary array used by the algorithm
    List<int> w = _w;
    if (w==null) _w = w = new List<int>(_ROUNDS);
    
    // Loop variables
    bool paddingStarted = false;
    bool done = false;
    
    // While we have unprocessed blocks
    while (!done) {
      if (chunkLength>=_BLOCK_LENGTH_IN_BYTES) {
        // This is not the last block. All integers can be constructed from the received bytes.
        for (int wi=0; wi<16; wi++) {
          int bi = chunkOffset + wi*4;
          w[wi] = w[wi] = (chunkBytes[bi] << 56) | (chunkBytes[bi+1] << 48) | (chunkBytes[bi+2] << 40) | (chunkBytes[bi+3] << 32) | (chunkBytes[bi+4] << 24) | (chunkBytes[bi+5] << 16) | (chunkBytes[bi+6] << 8) | chunkBytes[bi+7];
        }
        chunkOffset += _BLOCK_LENGTH_IN_BYTES;
        chunkLength -= _BLOCK_LENGTH_IN_BYTES;
        done = chunkLength <= 0 && !isLastChunk;
      }
      else {
        // If this not the last block, put bytes into the buffer and stop.
        if (!isLastChunk) {
          if (chunkLength>0) {
            _buffer.addAll(chunkBytes.getRange(chunkOffset, chunkLength));
          }
          break;
        }
        
        // Do SHA1/SHA2 padding.
        
        // Index of the integer we are constructing
        int wi = 0;
        
        if (!paddingStarted)  {          
          // Use input bytes to construct the integer
          int j = (chunkLength/_INTEGER_SIZE_IN_BYTES).toInt();
          for (; wi < j; wi++) {
            int bi = chunkOffset + wi*_INTEGER_SIZE_IN_BYTES;
            w[wi] = w[wi] = (chunkBytes[bi] << 56) | (chunkBytes[bi+1] << 48) | (chunkBytes[bi+2] << 40) | (chunkBytes[bi+3] << 32) | (chunkBytes[bi+4] << 24) | (chunkBytes[bi+5] << 16) | (chunkBytes[bi+6] << 8) | chunkBytes[bi+7];
          }
          
          // For this integer we need "one bit + zero bits" padding to construct the integer
          int intWherePaddingStarts = 0;
          for (int b=0; b<_INTEGER_SIZE_IN_BYTES; b++) {
            int wbi = wi*_INTEGER_SIZE_IN_BYTES+b;
            if (wbi<chunkLength) {
              // Use input byte
              intWherePaddingStarts |= (chunkBytes[chunkOffset+wbi] & 0xFF) << ((_INTEGER_SIZE_IN_BYTES-1-b)*8);
            }
            else if (wbi==chunkLength && !paddingStarted) {
              // Use "1 one bit + 7 zero bits" byte
              intWherePaddingStarts |= 0x80 << ((_INTEGER_SIZE_IN_BYTES-1-b)*8);
              paddingStarted = true;
            }
            else {
              // Use zero byte
            }
          }
          w[wi] = intWherePaddingStarts;
          wi++;
        }
        
        // The remaining integers are zero
        for (; wi<16; wi++) w[wi] = 0;
        
        // The last two integers is length in bits.
        // If we don't have space for the length,
        // we add a block with zeroes + message length.
        if (chunkLength <= _BLOCK_LENGTH_IN_BYTES - 2*(_INTEGER_SIZE_IN_BYTES) - 1) {
          int messageLengthInBits = _messageLength;
          w[14] = _INTEGER_MASK & (messageLengthInBits >> _INTEGER_SIZE_IN_BITS); 
          w[15] = _INTEGER_MASK & messageLengthInBits;
          done = true;
        }
        else {
          chunkLength = 0;
        }
      }
      
      // Extend the integers
      for (int i=16; i<_ROUNDS; i++) {
        int s0 = _rightRotate64(w[i-15], 1) ^ _rightRotate64(w[i-15], 8) ^ (w[i-15] >> 7);
        int s1 = _rightRotate64(w[i-2], 19) ^ _rightRotate64(w[i-2], 61) ^ (w[i-2] >> 6);
        w[i] = _INTEGER_MASK & w[i-16] + s0 + w[i-7] + s1;
      }
      
      // Main loop
      int a = h0;
      int b = h1;
      int c = h2;
      int d = h3;
      int e = h4;
      int f = h5;
      int g = h6;
      int h = h7;
      List<int> k = _constants;
      for (int i=0; i<_ROUNDS; i++) {
        int s0 = _rightRotate64(a, 28) ^ _rightRotate64(a, 34) ^ _rightRotate64(a, 39);
        int maj = (a & b) ^ (a & c) ^ (b & c);
        int t2 = _INTEGER_MASK & (s0 + maj);
        int s1 = _rightRotate64(e, 14) ^ _rightRotate64(e, 18) ^ _rightRotate64(e, 41);
        int ch = (e & f) ^ ((_INTEGER_MASK ^ e) & g);
        int t1 = _INTEGER_MASK & (h + s1 + ch + k[i] + w[i]);
        h = g;
        g = f;
        f = e;
        e = _INTEGER_MASK & (d + t1);
        d = c;
        c = b;
        b = a;
        a = _INTEGER_MASK & (t1 + t2);
      }
      h0 = _INTEGER_MASK & (a + h0);
      h1 = _INTEGER_MASK & (b + h1);
      h2 = _INTEGER_MASK & (c + h2);
      h3 = _INTEGER_MASK & (d + h3);
      h4 = _INTEGER_MASK & (e + h4);
      h5 = _INTEGER_MASK & (f + h5);
      h6 = _INTEGER_MASK & (g + h6);
      h7 = _INTEGER_MASK & (h + h7);
    }
    _h0 = h0;
    _h1 = h1;
    _h2 = h2;
    _h3 = h3;
    _h4 = h4;
    _h5 = h5;
    _h6 = h6;
    _h7 = h7;
    if (isLastChunk) return _createDigestByteList([h0, h1, h2, h3, h4, h5, h6, h7]);
    else return null;
  }
}