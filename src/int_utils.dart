// 
// Copyright 2012 jban332 <jban332@gmail.com>.
// Developed in the European Union and is therefore free of cryptography
// export restrictions.
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

class _IntUtils {
  static int leftRotate32(int value, int bits) {
    value = 0xFFFFFFFF & value;
    return (0xFFFFFFFF & (value << bits)) | (value >> (32 - bits));
  }
  
  static int rightRotate32(int value, int bits) {
    value = 0xFFFFFFFF & value;
    return (0xFFFFFFFF & (value << (32-bits))) | (value >> bits);
  }
  
  static int leftRotate64(int value, int bits) {
    value =  0xFFFFFFFFFFFFFFFF & value;
    return (0xFFFFFFFFFFFFFFFF & (value << bits)) | (value >> (32 - bits));
  }
  
  static int rightRotate64(int value, int bits) {
    value =  0xFFFFFFFFFFFFFFFF & value;
    return (0xFFFFFFFFFFFFFFFF & (value << (64-bits))) | (value >> bits);
  }
}