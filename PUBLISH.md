```
cd Saro.Dat

# dotnet nuget remove source nuget.org

dotnet build -c Release

dotnet nuget add source https://api.nuget.org/v3/index.json -n nuget.org \
    -u j@saro.me \
    -p [발급받은_API_KEY] \
    --store-password-in-clear-text
```
