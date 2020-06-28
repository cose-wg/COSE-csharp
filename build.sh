#!/bin/bash

set -ev
ls

echo $SLN
echo $VERSION
echo $FRAMEWORK


cd COSE

#mono ../nuget.exe restore $SLN
#nuget.exe restore $SLN

# $NUGET restore $SLN
dotnet restore --verbosity detailed $SLN
dotnet build --framework=$FRAMEWORK $SLN
dotnet test --framework=$FRAMEWORK $SLN
#xbuild /p:Configuration=$VERSION $SLN

# mono ../testrunner/NUnit.ConsoleRunner.3.5.0/tools/nunit3-console.exe ./COSE.Tests/bin/$VERSION/$TARGET/COSE.Tests.dll

