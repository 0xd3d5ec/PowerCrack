# Power-Bulk Rename
ls | %{Rename-Item $_ -NewName ("NEW-FILE-NAME-{0}.EXTENSION" -f $nr++)}
