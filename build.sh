#!/bin/bash

set -ev
ls

echo $SLN
echo $VERSION
echo $TARGET

mono nuget.exe restore COSE/$SLN

cd COSE

ls



msbuild /p:Configuration=$VERSION $SLN

mono ../testrunner/NUnit.ConsoleRunner.3.5.0/tools/nunit3-console.exe ./COSE.Tests/bin/$VERSION/$TARGET/COSE.Tests.dll

