<?php

namespace Tuijncode\LaravelWaf\Console\Commands;

use Illuminate\Console\Command;
use Tuijncode\LaravelWaf\Services\AutoBanManager;

class WafUnbanCommand extends Command
{
    protected $signature = 'waf:unban {ip : The IP address to unban}';

    protected $description = 'Lift a standing auto-ban for an IP address';

    public function handle(AutoBanManager $bans): int
    {
        $ip = (string) $this->argument('ip');

        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            $this->error("'{$ip}' is not a valid IP address.");

            return self::INVALID;
        }

        if ($bans->lift($ip)) {
            $this->info("Lifted the ban for {$ip}.");
        } else {
            $this->line("No standing ban for {$ip}.");
        }

        return self::SUCCESS;
    }
}
