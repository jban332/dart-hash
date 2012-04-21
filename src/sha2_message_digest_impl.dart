// 
// Copyright 2012 jban332 <jban332@gmail.com>.
// 
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.
// 

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
  
  void add(List<int> bytes, [int offset, int length]) {
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
  
  List<int> build([List<int> bytes = const [], int offset, int length]) {
    if (offset==null) offset = 0;
    if (length==null) length = bytes.length;
    List<int> d = _updateWithChunk(bytes, offset, length, true);
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
