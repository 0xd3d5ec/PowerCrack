# Power-Bulk Rename
```powershell
ls | %{Rename-Item $_ -NewName ("NEW-FILE-NAME-{0}.EXTENSION" -f $nr++)}
```
