// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package api

import (
	"github.com/go-openapi/runtime/middleware"
	"github.com/sigstore/fulcio/pkg/generated/restapi/operations"
)

const homePage = `<!DOCTYPE html>
<html lang="en-us">
<head>
<meta property="og:title" content="sigstore" />
<meta property="og:description" content="A non-profit, public good software signing &amp; transparency service" />
<meta property="og:type" content="website" />
<meta property="og:url" content="/" />
<meta name="description" content="A non-profit, public good software signing &amp; transparency service" />
<meta charset="utf-8">
  <title>sigstore</title>

  <link href="https://fonts.googleapis.com/css?family=Catamaran:400,600" rel="stylesheet">
</head>
  <body>
    <h1>
    Fulcio Server
    </h1>
    <h2>
      A non-profit, public good software signing &amp; transparency service.
      <p>To learn more visit <a href="https://sigstore.dev">Sigstore project page</a></p>
    </h2>
<footer>
  <p>Copyright © sigstore a Series of LF Projects, LLC For web site terms of use, trademark policy and general project policies please see <a href="https://lfprojects.org">https://lfprojects.org</a>.<p/>
</footer>
  </body>
</html>
`

func HomePageHandler(params operations.HomepageParams) middleware.Responder {
	return operations.NewHomepageOK().WithPayload(homePage).WithContentType("text/html")
}
