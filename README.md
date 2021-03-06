jerry-oauth
===========

Common Java functionality for working with OAuth.

`jerry-oauth` is a module library for the uber `jerry` library project. This module provides helper functionality 
for working with OAuth both at the client end, as well as the server side. Contains helper methods to generate
nonce etc, and also implementations for a nonce server, oauth token server etc.

For more information on the project, refer to https://github.com/sangupta/jerry project.

Releases
--------

**Current Development**

**0.9.0**

* Implementations for Yahoo, GitHub, DropBox, LinkedIn, MicrosoftLive added
* Updated social network scope constants to include the entire list
* Abstracted verification code param name in OAuth services
* Changed getLoginURL() return type from String to TokenAndUrl - thus clients need not keep track of what is to be used and what not
* Decode url parameters in UrlParamTokenExtractor
* Other bug fixes and refactorings

**0.1.0**

* Base implementations for OAuth 1.0 and 2.0 which clients can inherit
* Default implementation for Google, Facebook and Twitter added
* In-memory implementation for NONCE verifier
* In-memory implementation for OAuth token generator
* Utility methods to generate OAuth headers when making requests
* Utility client to send OAuth signed requests

Downloads
---------

The library can be downloaded from Maven Central using:

```xml
<dependency>
    <groupId>com.sangupta</groupId>
    <artifactId>jerry-oauth</artifactId>
    <version>0.9.0</version>
</dependency>
```

Versioning
----------

For transparency and insight into our release cycle, and for striving to maintain backward compatibility, 
`jerry-oauth` will be maintained under the Semantic Versioning guidelines as much as possible.

Releases will be numbered with the follow format:

`<major>.<minor>.<patch>`

And constructed with the following guidelines:

* Breaking backward compatibility bumps the major
* New additions without breaking backward compatibility bumps the minor
* Bug fixes and misc changes bump the patch

For more information on SemVer, please visit http://semver.org/.

License
-------

```	
jerry-oauth : Common Java OAuth functionality
Copyright (c) 2012-2014, Sandeep Gupta

	http://sangupta.com/projects/jerry-oauth

The project uses various other libraries that are subject to their
own license terms. See the distribution libraries or the project
documentation for more details.

The entire source is licensed under the Apache License, Version 2.0 
(the "License"); you may not use this work except in compliance with
the LICENSE. You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
