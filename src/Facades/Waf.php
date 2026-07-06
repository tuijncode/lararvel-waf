<?php

namespace Tuijncode\LaravelWaf\Facades;

use Illuminate\Support\Facades\Facade;
use Tuijncode\LaravelWaf\Services\InspectionResult;
use Tuijncode\LaravelWaf\Services\WafInspector;

/**
 * @method static InspectionResult inspect(\Illuminate\Http\Request $request)
 * @method static InspectionResult|null handle(\Illuminate\Http\Request $request)
 *
 * @see WafInspector
 */
class Waf extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'laravel-waf';
    }
}
