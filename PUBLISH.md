- publish
```
dotnet clean
dotnet pack -c Release

dotnet nuget push bin/Release/saro-dat.1.2.0.nupkg -s nuget.org -k [API_KEY]
```
