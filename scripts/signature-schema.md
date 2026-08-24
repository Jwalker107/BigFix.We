# Definition for BigFix Inventory Signature Schema
Each BigFix Inventory Custom Signature should be composed as follows:

1) Each Inventory signature should be an XML file
2) The XML file content must conform to the BigFix Inventory Signature Schema.  The intent is to load these through Catalog Customizations -> Import
3) The XML file should embed descriptive text as XML Frontmatter comments, i.e.

```
<!--
Description: "Inventory Signature Description"
Author: "Jane Doe"
uploadedOn: "2015-02-19 11:05:33.993"
Publisher: "The publisher of the detected product"
ProductName: "The name of the product"
Release: "1.2.3-x"
Keywords: "searchable keywords, separated by commas"
-->
```
4) The XML filename should match the naming convention '<Publisher>-<Product>-<Release>-<Variant>.xml'  The 'Variant' is optional and is meant to distinguish between signatures for the same product on differnet operating systems (i.e. 'Windows', 'Mac', 'Ubuntu'); different detection methods for the same product (i.e. 'PackageData' or 'FilePath').  Any characters that are illegal for a filename, such as '?' or '*', should be omitted.

5) When exporting from bigfix.me, the XML content of a signature can be exported via
```
SELECT
CONVERT(varchar(max),CAST(fileContents AS varbinary(max))) AS TextResult
FROM dbo.signature
```
A complete example is thus would be a file named 'VMware-VMWare Tools-7.4-Windows.xml' with the following content:
```xml
<?xml version="1.0" encoding="utf-8"?>
<!--
Description: "VMWare Tools 7.4 detection for Windows"
Author: "jmatlock"
uploadedOn: "2015-02-19 11:05:33.993"
Publisher: "VMWare"
ProductName: "VMWare Tools"
Release: "7.4.*"
Keywords: "VMWare, Virtual Machine, Windows, Software, Utility, Driver"
-->
<SoftwareIdentityCatalog exportTimeStamp="2015-05-20T15:38:24Z">
  <Software name="VMware Tools" vendor="VMware" uniqueId="e9822f60-ff05-11e4-9d9c-005056007f46" version="7.4">
    <Signature uniqueId="e91cb6d0-ff05-11e4-9d9b-005056007f46" modified="2015-05-20T15:35:57Z" created="2015-05-20T15:35:57Z">
      <AND>
        <OR>
          <PackageFilter name="vmware-tools-core" vendor="VMware" version="7.4.*" />
        </OR>
      </AND>
    </Signature>
  </Software>
</SoftwareIdentityCatalog>
```