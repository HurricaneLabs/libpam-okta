# Okta PAM module

PAM module implementing Okta multi-factor authentication.

## Installation

TBD

## Usage

This module support several Okta authentication factors, but not all, as I only
had some available to me for testing. In addition, it supports authentication
via device authorization grant OAUTH.

At a minimum, add this line to your PAM configuration file:

```
auth required pam_okta.so tenant=YOURTENANT.okta.com
```

### Supported factors

The following factors are supported. Support for additional factors may come
in future releases. Please submit an issue and/or PR if there are factors you'd
like to see supported.

* Okta verify (push)
* Okta verify (TOTP)
* Google authenticator (TOTP)
* Yubikey
* Phone call verification
* SMS verification

### Device Authorization Grant Flow

To use device authorization grant OAUTH, you must also specify `client_id` in
the PAM configuration line. This is obtained from the application configuration
in Okta. You can find more information about configuring Device Authorization
[here](https://developer.okta.com/docs/guides/device-authorization-grant/main/).

In addition to the `client_id`, if your Okta uses email address for login but
your OS users do not, you'll need to specify one of the following two options:

1. You can specify `username_suffix=example.com`, which will add `@example.com`
   to the OS username when verifying the user in the device grant. This will
   ensure that only users with that domain are able to authenticate, should you
   have external users with potentially overlapping usernames.
2. If you are not worried about username collisions, you can instead specify
   `check_username_prefix`, which will only compare the prefix from the Okta
   username against the OS username.

In order to use device authorization flow, a user can enter an empty password,
which will cause the PAM module to print out the URL which can be used to
authenticate.

Version History
---------------

### Version 0.1.0 (2021-11-19)

-   Initial release

License Info
------------

The MIT License (MIT)

Copyright (c) 2021 Hurricane Labs LLC

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
