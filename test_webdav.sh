#!/bin/bash

echo "Testing WebDAV server with testuser..."

# Test 1: List directory contents using curl with basic authentication
echo "Test 1: Listing root directory contents"
curl -X PROPFIND -u testuser:password -H "Depth: 1" -H "Content-Type: text/xml" \
  http://localhost:8088/ -s | xmllint --format -

echo -e "\nTest 2: Trying to create a directory"
curl -X MKCOL -u testuser:password http://localhost:8088/testdir/ -v

echo -e "\nTest 3: Listing directory after creating testdir"
curl -X PROPFIND -u testuser:password -H "Depth: 1" -H "Content-Type: text/xml" \
  http://localhost:8088/ -s | xmllint --format -

echo -e "\nTest 4: Uploading a test file"
echo "This is a test file" | curl -X PUT -u testuser:password \
  --data-binary @- http://localhost:8088/testdir/testfile.txt -v

echo -e "\nTest 5: Downloading the test file"
curl -X GET -u testuser:password http://localhost:8088/testdir/testfile.txt -v

echo -e "\nTest 6: Deleting the test file"
curl -X DELETE -u testuser:password http://localhost:8088/testdir/testfile.txt -v

echo -e "\nTest 7: Removing the test directory"
curl -X DELETE -u testuser:password http://localhost:8088/testdir/ -v

echo -e "\nWebDAV testing completed!"