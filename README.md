# Resonant Core's Anti-CSRF Library

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
        'form_token`,
        function($lock_to = null) {
            static $csrf = null;
            if ($csrf === null) {
                $csrf = new Resonantcore\AntiCSRF\AntiCSRF();
            }
            return $csrf->insertToken($lock_to, false);
        }
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
