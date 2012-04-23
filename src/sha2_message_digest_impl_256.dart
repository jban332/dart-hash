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

class _Sha2MessageDigestImpl256 extends _Sha2MessageDigestImplBase {
  
  // Constants
  static final List<int> _constants = const [
                                             0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                                             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                                             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                                             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                                             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                                             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                                             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                                             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
  static final int _BLOCK_LENGTH_IN_BYTES = 64;
  static final int _ROUNDS = 64;
  static final int _INTEGER_SIZE_IN_BYTES = 4;
  static final int _INTEGER_SIZE_IN_BITS = 32;
  static final int _INTEGER_MASK = 0xFFFFFFFF;
  
  int get blockLength() => _BLOCK_LENGTH_IN_BYTES;
  int get hashLength() => 32;
  
  // Initial values for SHA2-256.
  // SHA2-224 has different initial values.
  static final List<int> _initialValues256 = const [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  List<int> get _initialValues() => _initialValues256;
  
  // Creates a result array.
  // SHA2-224 overrides this.
  List<int> _createDigestByteList(List<int> integers) {
    List<int> array = new List(4*integers.length);
    for (int i=0; i<integers.length; i++) {
      int h = integers[i];
      int byteIndex = 4*i;
      array[byteIndex] = 0xFF & (h >> 24);
      array[byteIndex+1] = 0xFF & (h >> 16);
      array[byteIndex+2] = 0xFF & (h >> 8);
      array[byteIndex+3] = 0xFF & (h >> 0);
    }
    return array;
  }
  
  // Right rotate function
  static int _rightRotate32(int value, int bits) => _IntUtils.rightRotate32(value, bits);
  
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
          w[wi] = (chunkBytes[bi] << 24) | (chunkBytes[bi+1] << 16) | (chunkBytes[bi+2] << 8) | chunkBytes[bi+3];
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
            w[wi] = (chunkBytes[bi] << 24) | (chunkBytes[bi+1] << 16) | (chunkBytes[bi+2] << 8) | chunkBytes[bi+3];
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
        int s0 = _rightRotate32(w[i-15], 7) ^ _rightRotate32(w[i-15], 18) ^ (w[i-15] >> 3);
        int s1 = _rightRotate32(w[i-2], 17) ^ _rightRotate32(w[i-2], 19) ^ (w[i-2] >> 10);
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
        int s0 = _rightRotate32(a, 2) ^ _rightRotate32(a, 13) ^ _rightRotate32(a, 22);
        int maj = (a & b) ^ (a & c) ^ (b & c);
        int t2 = _INTEGER_MASK & (s0 + maj);
        int s1 = _rightRotate32(e, 6) ^ _rightRotate32(e, 11) ^ _rightRotate32(e, 25);
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