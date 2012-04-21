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

void forLinesInFile(File file, void callback(String args)) {
  List<String> lines = file.readAsLinesSync();
  for (String line in lines) {
    callback(line);
  }
}

String _byteArrayToHexString(List<int> bytes) {
  if (bytes==null) return null;
  StringBuffer sb = new StringBuffer();
  final hexCharacters = const ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"];
  for (int i=0; i<bytes.length; i++) {
    int v = bytes[i];
    if (v<0 || v>255) throw new Exception("Expected a byte array, but at least one item ${v} is not an integer in the range 0...255.");
    sb.add(hexCharacters[(v >> 4) & 0xF]);
    sb.add(hexCharacters[v & 0xF]);
  }
  return sb.toString();
}

// This test vector files have the format:
//
// [ALGORITHM_NAME] [INPUT_STRING] [INPUT_STRING_REPEAT_COUNT] [OUTPUT_IN_HEX]
// ...
void testMessageDigests() {
  StringBuffer inputSb = new StringBuffer();
  String previousPattern = null;
  forLinesInFile(new File("test/message_digest_data.txt"), (String line) {
    if (line.length == 0) return;
    else if (line.startsWith("#")) {
      print(line.substring(1).trim());
      return;
    }
    
    // Read test vector
    List<String> args = line.split(" ");
    String algorithmName = args[0];
    String pattern = args[1];
    int patternTimes = Math.parseInt(args[2]);
    String expected = args[3];
    
    // Construct input
    if (previousPattern!=pattern || inputSb.length>patternTimes*pattern.length) inputSb.clear();
    assert(pattern.length>0);
    while(inputSb.length < patternTimes*pattern.length) inputSb.add(pattern);
    previousPattern = pattern;
    List<int> input = inputSb.toString().charCodes();
    int splitIndex = (input.length/2).toInt();
    List<int> inputFirstHalf = input.getRange(0, splitIndex);
    List<int> inputSecondHalf = input.getRange(splitIndex, input.length - splitIndex);
    
    
    // Construct hash function
    MessageDigest md;
    switch (algorithmName) {
      case "sha1": md = new Sha1MessageDigest(); break;
      case "sha2-224": md = new Sha2MessageDigest.withLength224(); break;
      case "sha2-256": md = new Sha2MessageDigest.withLength256(); break;
      case "sha2-384": md = new Sha2MessageDigest.withLength384(); break;
      case "sha2-512": md = new Sha2MessageDigest.withLength512(); break;
      default:
        print("Error: Unrecognized digest algorithm name '${algorithmName}'.");
        return;
    }
    
    // Calculate hash value using methods: build(input)
    String actual = _byteArrayToHexString(md.build(input));
    // Verify correctness
    if (actual!=expected) throw new Exception("Algorithm: ${algorithmName}\nInput: ${patternTimes} x '${pattern}'\nActual:   ${actual}\nExpected: ${expected}");
    
    // Calculate hash value using methods: add(input), build()
    md.reset();
    md.add(input);
    actual = _byteArrayToHexString(md.build());
    // Verify correctness
    if (actual!=expected) throw new Exception("Algorithm: ${algorithmName}\nInput: ${patternTimes} x '${pattern}'\nActual:   ${actual}\nExpected: ${expected}");
    
    // Calculate hash value using methods: add(input0), build(input1)
    md.reset();
    md.add(inputFirstHalf);
    actual = _byteArrayToHexString(md.build(inputSecondHalf));
    // Verify correctness
    if (actual!=expected) throw new Exception("Algorithm: ${algorithmName}\nInput: ${patternTimes} x '${pattern}'\nActual:   ${actual}\nExpected: ${expected}");
    
    // Calculate hash value using methods: add(input0), add(input1), build()
    md.reset();
    md.add(inputFirstHalf);
    md.add(inputSecondHalf);
    actual = _byteArrayToHexString(md.build());
    // Verify correctness
    if (actual!=expected) throw new Exception("Algorithm: ${algorithmName}\nInput: ${patternTimes} x '${pattern}'\nActual:   ${actual}\nExpected: ${expected}");
  });
  print("Done.");
}