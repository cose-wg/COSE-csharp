#!/bin/bash

set -ev
cd COSE

echo $SLN
echo $VERSION
echo $TARGET
ls

mono nuget restore $SLN

msbuild /p:Configuration=$VERSION $SLN

mono ../testrunner/NUnit.ConsoleRunner.3.5.0/tools/nunit3-console.exe ./COSE.Tests/bin/$VERSION/$TARGET/COSE.Tests.dll

