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

class _Sha1MessageDigestImpl implements Sha1MessageDigest {
  // Constants
  static final int _BLOCK_LENGTH_IN_BYTES = 64;
  static final int _ROUNDS = 80;
  static final int _INTEGER_SIZE_IN_BYTES = 4;
  static final int _INTEGER_SIZE_IN_BITS = 32;
  static final int _INTEGER_MASK = 0xFFFFFFFF;
  
  // Length of the message
  int _messageLength = 0;
  
  // Bytes that were not enough to form a block
  List<int> _buffer;
  
  // Variables used by the hash function
  int _h0, _h1, _h2, _h3, _h4;
  List<int> _w;
  
  _Sha1MessageDigestImpl() : _buffer = [] {
    reset();
  }
  
  int get blockLength() => _BLOCK_LENGTH_IN_BYTES;
  int get hashLength() => 20;
  
  void addByteList(List<int> bytes, [int offset, int length]) {
    assert(bytes!=null);
    if (offset==null) offset = 0;
    if (length==null) length = bytes.length;
    // In checked mode verify that all items between 0 <= x <= 255.
    assert(() {
      for (int i=0; i<length; i++) {
        int b = bytes[offset+i];
        assert(b is int && 0<=b && b<=255);
      }
      return true;
    }());
    _updateWithChunk(bytes, offset, length, false);
  }
  
  List<int> buildWithByteList(List<int> bytes, [int offset, int length]) {
    if (bytes==null) bytes = const [];
    if (offset==null) offset = 0;
    if (length==null) length = bytes.length;
    // In checked mode verify that all items between 0 <= x <= 255.
    assert(() {
      for (int i=0; i<length; i++) {
        int b = bytes[offset+i];
        assert(b is int && 0<=b && b<=255);
      }
      return true;
    }());
    List<int> d = _updateWithChunk(bytes, offset, length, true);
    reset();
    return d;
  }
  
  List<int> build() {
    List<int> d = _updateWithChunk(const [], 0, 0, true);
    reset();
    return d;
  }
  
  void reset() {
    // Clear buffer
    _buffer.clear();
    
    // Set length at 0
    _messageLength = 0;
    
    // Initialize variables
    _h0 = 0x67452301;
    _h1 = 0xEFCDAB89;
    _h2 = 0x98BADCFE;
    _h3 = 0x10325476;
    _h4 = 0xC3D2E1F0;
  }
  
  List<int> _updateWithChunk(List<int> chunkBytes, int chunkOffset, int chunkLength, bool isLastBlock) {
    if (chunkLength==0 && !isLastBlock) return null;
    _messageLength += chunkLength*8;
    
    // If there are bytes in the buffer
    if (_buffer.length > 0 && chunkBytes !== _buffer) {
      // Fill the buffer
      int d = Math.min(chunkLength, _BLOCK_LENGTH_IN_BYTES - _buffer.length);
      _buffer.addAll(chunkBytes.getRange(chunkOffset, d));
      chunkOffset += d;
      chunkLength -= d;

      // Process the buffer if possible
      if (_buffer.length == _BLOCK_LENGTH_IN_BYTES) {
        _messageLength -= _buffer.length*8;
        _updateWithChunk(_buffer, 0, _buffer.length, false);
        _buffer.clear();
      }
      else {
        if (!isLastBlock) return null;
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
        done = chunkLength <= 0 && !isLastBlock;
      }
      else {
        // If this not the last block, put bytes into the buffer and stop.
        if (!isLastBlock) {
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
          int j = (chunkLength/4).toInt();
          for (; wi < j; wi++) {
            int bi = chunkOffset + wi*4;
            w[wi] = (chunkBytes[bi] << 24) | (chunkBytes[bi+1] << 16) | (chunkBytes[bi+2] << 8) | chunkBytes[bi+3];
          }
          
          // For this integer we need "one bit + zero bits" padding to construct the integer
          int intWherePaddingStarts = 0;
          for (int b=0; b<4; b++) {
            int wbi = wi*4+b;
            if (wbi<chunkLength) {
              // Use input byte
              intWherePaddingStarts |= (chunkBytes[chunkOffset+wbi] & 0xFF) << ((3-b)*8);
            }
            else if (wbi==chunkLength && !paddingStarted) {
              // Use "1 one bit + 7 zero bits" byte
              intWherePaddingStarts |= 0x80 << ((3-b)*8);
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
        w[i] = _IntUtils.leftRotate32((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1);
      }
      
      // Main loop
      int a = h0;
      int b = h1;
      int c = h2;
      int d = h3;
      int e = h4;
      int f = 0;
      int k = 0;
      for (int i=0; i<_ROUNDS; i++) {
        if (i < 20) {
          f = (b & c) | ((_INTEGER_MASK ^ b) & d);
          k = 0x5A827999;
        }
        else if (i < 40) {
          f = b ^ c ^ d;
          k = 0x6ED9EBA1;
        }
        else if (i < 60) {
          f = (b & c) | (b & d) | (c & d);
          k = 0x8F1BBCDC;
        }
        else {
          f = b ^ c ^ d;
          k = 0xCA62C1D6;
        }
        int temp = _INTEGER_MASK & _IntUtils.leftRotate32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = _INTEGER_MASK & _IntUtils.leftRotate32(b, 30);
        b = a;
        a = temp;
      }
      h0 = _INTEGER_MASK & (h0 + a);
      h1 = _INTEGER_MASK & (h1 + b);
      h2 = _INTEGER_MASK & (h2 + c);
      h3 = _INTEGER_MASK & (h3 + d);
      h4 = _INTEGER_MASK & (h4 + e);
    }
    _h0 = h0;
    _h1 = h1;
    _h2 = h2;
    _h3 = h3;
    _h4 = h4;
    if (isLastBlock) {
      List<int> digestByteList = new List(20);
      int byteIndex = 0;
      for (int h in [h0, h1, h2, h3, h4]) {
        digestByteList[byteIndex] = (h >> 24) & 0xFF;
        digestByteList[byteIndex+1] = (h >> 16) & 0xFF;
        digestByteList[byteIndex+2] = (h >> 8) & 0xFF;
        digestByteList[byteIndex+3] = (h >> 0) & 0xFF;
        byteIndex += 4;
      }
      return digestByteList;
    }
    else return null;
  }
}