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

#library("generate_test_data");
#import("dart:io");

String getTestDirectory() {
  for (String dir in ["./", "./test/"]) {
    if (new File("${dir}/test_data_generator.java").existsSync()) return dir;
  }
  throw new Exception("Could not find the directory in ${new File("").fullPathSync()}.");
}

void compileAndRun() {
  print("Compiling Java class.");
  Process process = new Process.start("javac", ["${getTestDirectory()}/test_data_generator.java"]);
  process.stderr.onData = () => stderr.write(process.stderr.read());
  process.stdout.onData = () => stdout.write(process.stdout.read());
  process.onError = (Exception e) { print("Error: ${e.toString()}."); };
  process.onExit = (int exitCode) {
    run();
  };
}

void run() {
  print("Running Java class.");
  String javaClass = "test_data_generator";
  Process process = new Process.start("java", ["-cp", getTestDirectory(), javaClass, getTestDirectory()]);
  process.stderr.onData = () => stderr.write(process.stderr.read());
  process.stdout.onData = () => stdout.write(process.stdout.read());
  process.onError = (Exception e) { print("Error: ${e.toString()}."); };
  process.onExit = (int exitCode) {
    new File("${getTestDirectory()}/${javaClass}.class").deleteSync();
    print("Done.");
  };
}

void main() {
  compileAndRun();
}
