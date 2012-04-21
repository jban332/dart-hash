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
