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

class _Sha2MessageDigestImpl384 extends _Sha2MessageDigestImpl512 {
  
  // SHA2-384 has different initial values than SHA2-512.
  static final List<int> _initialValues384 = const [0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
                                                    0x9159015a3070dd17, 0x152fecd8f70e5939,
                                                    0x67332667ffc00b31, 0x8eb44a8768581511,
                                                    0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4];
  List<int> get _initialValues() => _initialValues384;
  
  // SHA2-384 outputs two integers less than SHA2-512.
  List<int> _createDigestByteList(List<int> integers) => super._createDigestByteList(integers.getRange(0, 6));
  
  int get digestLength() => 48;
}