<?php

declare(strict_types=1);

namespace Denosys\Auth\Authorization\Policy;

use Denosys\Database\Connection\Connection;

class DatabasePolicySource implements PolicySourceInterface
{
    public function __construct(
        private readonly Connection $connection,
        private readonly string $table = 'policies',
    ) {}

    /**

     * @return array<string, mixed>

     */

public function load(): array

    {
        $rows = $this->connection->select(
            "SELECT * FROM {$this->table} WHERE active = 1 ORDER BY priority DESC"
        );

        $policies = [];

        foreach ($rows as $row) {
            $row = (array) $row;

            // Parse action (might be JSON array)
            $action = $row['action'];
            if (is_string($action) && str_starts_with($action, '[')) {
                $decoded = json_decode($action, true);
                if (is_array($decoded)) {
                    $action = $decoded;
                }
            }

            $policies[] = new Policy(
                subject: $row['subject'],
                action: $action,
                resource: $row['resource'],
                effect: $row['effect'] ?? 'allow',
                condition: null, // Database policies can't have closures
                priority: (int) ($row['priority'] ?? 0),
            );
        }

        return $policies;
    }
}
