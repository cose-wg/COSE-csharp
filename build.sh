#!/bin/bash

set -ev
ls

echo $SLN
echo $VERSION
echo $TARGET


cd COSE

ls

mono ../nuget.exe
mono ../nuget.exe restore $SLN

msbuild /p:Configuration=$VERSION $SLN
#xbuild /p:Configuration=$VERSION $SLN

mono ../testrunner/NUnit.ConsoleRunner.3.5.0/tools/nunit3-console.exe ./COSE.Tests/bin/$VERSION/$TARGET/COSE.Tests.dll

