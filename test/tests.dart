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
    String actual = _byteArrayToHexString(md.buildWithByteList(input));
    // Verify correctness
    if (actual!=expected) throw new Exception("Algorithm: ${algorithmName}\nInput: ${patternTimes} x '${pattern}'\nActual:   ${actual}\nExpected: ${expected}");
    
    // Calculate hash value using methods: add(input), build()
    md.reset();
    md.addByteList(input);
    actual = _byteArrayToHexString(md.build());
    // Verify correctness
    if (actual!=expected) throw new Exception("Algorithm: ${algorithmName}\nInput: ${patternTimes} x '${pattern}'\nActual:   ${actual}\nExpected: ${expected}");
    
    // Calculate hash value using methods: add(input0), build(input1)
    md.reset();
    md.addByteList(inputFirstHalf);
    actual = _byteArrayToHexString(md.buildWithByteList(inputSecondHalf));
    // Verify correctness
    if (actual!=expected) throw new Exception("Algorithm: ${algorithmName}\nInput: ${patternTimes} x '${pattern}'\nActual:   ${actual}\nExpected: ${expected}");
    
    // Calculate hash value using methods: add(input0), add(input1), build()
    md.reset();
    md.addByteList(inputFirstHalf);
    md.addByteList(inputSecondHalf);
    actual = _byteArrayToHexString(md.build());
    // Verify correctness
    if (actual!=expected) throw new Exception("Algorithm: ${algorithmName}\nInput: ${patternTimes} x '${pattern}'\nActual:   ${actual}\nExpected: ${expected}");
  });
  print("Done.");
}