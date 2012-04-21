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

/**
Example of use:
  // Create a MessageDigest
  MessageDigest md = new SomeMessageDigest();
  md.add(someData1);
  md.add(someData2);
  md.add(someData3);
  List<int> digest123 = md.build();

*/
interface MessageDigest {
  /**
  Number of bytes in a block.
  */
  int get blockLength();
  
  /**
  Number of bytes in a hash.
  */
  int get hashLength();
  
  /**
  Processes the bytes.
  */
  void add(List<int> bytes, [int offset, int length]);
  
  /**
  Process the bytes (if any) and returns the hash value. Before returning, reset() is invoked.
  */
  List<int> build([List<int> bytes, int offset, int length]);
  
  /**
  Restores the initial state.
  */
  void reset();
}