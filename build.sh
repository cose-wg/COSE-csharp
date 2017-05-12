#!/bin/bash
set -ev

cd COSE
nuget restore $SLN
msbuild /v:q /p:Configuration=$VERSION $SLN

mono ../testrunner/NUnit.ConsoleRunner.3.5.0/tools/nunit3-console.exe ./COSE.Tests/bin/$VERSION/$TARGET/COSE.Tests.dll

cd ..
#cd examples

#msbuild /v:q /p:Configuration=$VERSION examples.sln

#mono examples/examples/bin/$VERSION/$TARGET/examples.exe --cose Regressions
#mono examples/examples/bin/$VERSION/$TARGET/examples.exe --jose cookbook
