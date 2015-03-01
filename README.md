# Resonant Core's Anti-CSRF Library

[![Build Status](https://travis-ci.org/resonantcore/anti-csrf.svg?branch=master)](https://travis-ci.org/resonantcore/anti-csrf)

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

## Using it in Any Project

See `autoload.php` for an SPL autoloader.

## Using it with Twig templates

First, add a filter like this one:

```php
$twigEnv->addFunction(
    new \Twig_SimpleFunction(
        'form_token',
        function($lock_to = null) {
            return \Resonantcore\AntiCSRF\AntiCSRF::insertToken($lock_to, false);
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
    if (!empty($_POST)) {
        if (\Resonantcore\AntiCSRF\AntiCSRF::validateRequest()) {
            // Valid
        } else {
            // Log a CSRF attack attempt
        }
    }
```

## About Resonant Core

* [Our Website](https://resonantcore.net)
* [What is Resonant Core?](https://resonantcore.net/what/)
* [ResonantCore on Twitter](https://twitter.com/ResonantCore)
