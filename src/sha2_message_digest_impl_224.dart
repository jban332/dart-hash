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

class _Sha2MessageDigestImpl224 extends _Sha2MessageDigestImpl256 {
  
  // SHA2-224 has different initial values than SHA2-256.
  static final List<int> _initialValues224 = const [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
  List<int> get _initialValues() => _initialValues224;
  
  // SHA2-224 outputs one integer less than SHA-256.
  List<int> _createDigestByteList(List<int> integers) => super._createDigestByteList(integers.getRange(0, 7));
  
  int get digestLength() => 28;
}