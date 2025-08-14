# MozIDump

Extract the contents of Firefox’s IndexedDB into JSON format.

This is inspired by ntninja’s [`moz-idb-edit`](https://gitlab.com/ntninja/moz-idb-edit), itself inspried from a [Stack Overflow question](https://stackoverflow.com/questions/54920939/parsing-fb-puritys-firefox-idb-indexed-database-api-object-data-blob-from-lin).

Also, this is 💫 blazingly fast 🚀 because it is written in Rust 🦀.
While the Python version takes about 34 s to extract the data I care about, this program does the same in 340 ms.
This results in a 184 MB JSON file, so a very rough calculation gives a throughput of 500 MB/s.
