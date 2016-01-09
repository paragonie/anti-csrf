# Anti-CSRF Library

[![Build Status](https://travis-ci.org/paragonie/anti-csrf.svg?branch=master)](https://travis-ci.org/paragonie/anti-csrf)

## Motivation

There aren't any good session-powered CSRF prevention libraries. By good we mean:

* CSRF tokens can be restricted to any or all of the following:
  * A particular session
  * A particular HTTP URI
  * A particular IP address (optional)
* Multiple CSRF tokens can be stored
* CSRF tokens expire after one use
* An upper limit on the number of tokens stored with session data is enforced
  * In our implementation, the oldest are removed first

**Warning** - Do not use in any project where all `$_SESSION` data is stored 
client-side in a cookie. This will quickly run up the 4KB storage max for 
an HTTP cookie.

## Using it in Any Project

See `autoload.php` for an SPL autoloader.

## Using it with Twig templates

First, add a filter like this one:

```php
use \ParagonIE\AntiCSRF\AntiCSRF;
$twigEnv->addFunction(
    new \Twig_SimpleFunction(
        'form_token',
        function($lock_to = null) {
            static $csrf;
            if ($csrf === null) {
                $csrf = new AntiCSRF;
            }
            return $csrf->insertToken($lock_to, false);
        },
        ['is_safe' => ['html']]
    )
);
```

Next, call the newly created form_token function from your templates.

```twig
<form action="/addUser.php" method="post">
    {{ form_token("/addUser.php") }}

    {# ... the rest of your form here ... #}
</form>
```

## Validating a Request

```php
    $csrf = new \ParagonIE\AntiCSRF\AntiCSRF;
    if (!empty($_POST)) {
        if ($csrf->validateRequest()) {
            // Valid
        } else {
            // Log a CSRF attack attempt
        }
    }
```