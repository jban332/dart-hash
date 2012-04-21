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