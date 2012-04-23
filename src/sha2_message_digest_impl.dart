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

class _Sha2MessageDigestImpl {
  factory Sha2MessageDigest.withLength224() => new _Sha2MessageDigestImpl224();
  factory Sha2MessageDigest.withLength256() => new _Sha2MessageDigestImpl256();
  factory Sha2MessageDigest.withLength384() => new _Sha2MessageDigestImpl384();
  factory Sha2MessageDigest.withLength512() => new _Sha2MessageDigestImpl512();
}

class _Sha2MessageDigestImplBase implements Sha2MessageDigest {
  
  // Length of the message.
  int _messageLength = 0;
  
  // Bytes that were not enough to fill a block.
  List<int> _buffer;
  
  // Variables used by the hash function
  int _h0, _h1, _h2, _h3, _h4, _h5, _h6, _h7;
  List<int> _w;
  
  _Sha2MessageDigestImplBase() : _buffer = [] {
    reset();
  }
  
  // Initial values. Implemented by subclasses.
  abstract List<int> get _initialValues();
  
  // Implemented by subclasses.
  abstract List<int> _updateWithChunk(List<int> bytes, int offset, int length, bool isLastChunk);
  
  // Implemented by subclasses.
  abstract List<int> _createDigestByteList(List<int> integers);
  
  void addByteList(List<int> bytes, [int offset, int length]) {
    if (offset==null) offset = 0;
    if (length==null) length = bytes.length;
    assert(() {
      // In checked mode verify that this is really a byte array
      for (int i=0; i<length; i++) {
        int b = bytes[offset+i];
        assert(b is int && 0<=b && b<=255);
      }
      return true;
    }());
    _updateWithChunk(bytes, offset, length, false);
  }
  
  List<int> buildWithByteList(List<int> bytes, [int offset, int length]) {
    if (offset==null) offset = 0;
    if (length==null) length = bytes.length;
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
    List<int> initialValues = _initialValues;
    _h0 = initialValues[0];
    _h1 = initialValues[1];
    _h2 = initialValues[2];
    _h3 = initialValues[3];
    _h4 = initialValues[4];
    _h5 = initialValues[5];
    _h6 = initialValues[6];
    _h7 = initialValues[7];
  }
}
