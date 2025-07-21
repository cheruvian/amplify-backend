import { IBucket } from 'aws-cdk-lib/aws-s3';
import { Effect, Policy, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { Stack } from 'aws-cdk-lib';
import { AmplifyFault } from '@aws-amplify/platform-core';
import { StorageAction, StoragePath } from './types.js';
import { InternalStorageAction } from './private_types.js';

export type Permission = {
  actions: StorageAction[];
  /**
   * An s3 prefix that defines the scope of the actions
   */
  resources: string[];
};

/**
 * Generates IAM policies scoped to a single bucket
 */
export class StorageAccessPolicyFactory {
  private readonly stack: Stack;

  /**
   * Instantiate with the bucket to generate policies for
   */
  constructor(private readonly bucket: IBucket) {
    this.stack = Stack.of(bucket);
  }

  createPolicy = (
    permissions: Map<
      InternalStorageAction,
      {
        allow: Set<StoragePath>;
        deny: Set<StoragePath>;
        groupConditions?: string[];
      }
    >,
  ) => {
    if (permissions.size === 0) {
      throw new AmplifyFault('EmptyPolicyFault', {
        message: 'At least one permission must be specified',
      });
    }

    // DEBUG: Log what permissions are being processed for policy creation
    // eslint-disable-next-line no-console
    console.log(
      '🔧 StorageAccessPolicyFactory - Creating policy with permissions:',
      Array.from(permissions.entries()).map(([action, data]) => ({
        action,
        allowPaths: Array.from(data.allow),
        denyPaths: Array.from(data.deny),
        groupConditions: data.groupConditions,
      })),
    );

    // Group permissions by BOTH action AND group conditions to create separate statements
    // Entity access (no group conditions) and group access (with group conditions)
    // must generate separate IAM statements even for the same action
    const statementGroups = new Map<
      string, // Key: `${action}::${groupConditions?.join(',') || 'no-groups'}`
      {
        action: InternalStorageAction;
        allow: Set<StoragePath>;
        deny: Set<StoragePath>;
        groupConditions?: string[];
      }
    >();

    permissions.forEach((data, action) => {
      const groupKey = `${action}::${data.groupConditions?.join(',') || 'no-groups'}`;

      if (statementGroups.has(groupKey)) {
        // This shouldn't happen with proper orchestrator logic, but defensive coding
        const existing = statementGroups.get(groupKey)!;
        data.allow.forEach((path) => existing.allow.add(path));
        data.deny.forEach((path) => existing.deny.add(path));
      } else {
        statementGroups.set(groupKey, {
          action,
          allow: new Set(data.allow),
          deny: new Set(data.deny),
          groupConditions: data.groupConditions,
        });
      }
    });

    // DEBUG: Log the statement groups being created
    // eslint-disable-next-line no-console
    console.log(
      '🔧 StorageAccessPolicyFactory - Statement groups created:',
      Array.from(statementGroups.entries()).map(([groupKey, data]) => ({
        groupKey,
        action: data.action,
        allowPaths: Array.from(data.allow),
        denyPaths: Array.from(data.deny),
        groupConditions: data.groupConditions,
      })),
    );

    // Create separate IAM policy statements for each group
    const policyStatements = Array.from(statementGroups.values()).flatMap(
      (data) => {
        const { action, allow, deny, groupConditions } = data;

        const allowStatements =
          allow.size > 0
            ? [this.getStatement(allow, action, Effect.ALLOW, groupConditions)]
            : [];

        const denyStatements =
          deny.size > 0
            ? [this.getStatement(deny, action, Effect.DENY, groupConditions)]
            : [];

        return [...allowStatements, ...denyStatements];
      },
    );

    // DEBUG: Log final policy statements being created
    // eslint-disable-next-line no-console
    console.log(
      '🔧 StorageAccessPolicyFactory - Final policy statements:',
      policyStatements.map((stmt) => ({
        effect: stmt.effect,
        actions: stmt.actions,
        resources: stmt.resources,
        conditions: stmt.conditions,
      })),
    );

    const policy = new Policy(
      this.stack,
      `${this.stack.node.path}Access${this.stack.node.children.length}`,
      {
        statements: policyStatements,
      },
    );

    // DEBUG: Log the final policy document
    // eslint-disable-next-line no-console
    console.log(
      '🔧 StorageAccessPolicyFactory - Final policy document:',
      JSON.stringify(policy.document.toJSON(), null, 2),
    );

    return policy;
  };

  private getStatement = (
    s3Prefixes: Readonly<Set<StoragePath>>,
    action: InternalStorageAction,
    effect: Effect,
    groupConditions?: string[],
  ) => {
    // DEBUG: Log what statement is being created
    // eslint-disable-next-line no-console
    console.log(
      `🔧 StorageAccessPolicyFactory - Creating statement for action "${action}":`,
      {
        effect: effect.toString(),
        s3Prefixes: Array.from(s3Prefixes),
        groupConditions,
        bucketArn: this.bucket.bucketArn,
      },
    );

    const baseConditions: Record<string, Record<string, string[]>> = {};
    if (groupConditions && groupConditions.length > 0) {
      // OPTIMAL SOLUTION: StringLike with delimiters (Best of both worlds!)
      //
      // PROBLEM: Original array-based approach failed due to Cognito Identity limitations
      // SOLUTION: Use StringLike with delimiter-wrapped group names for exact matching
      //
      // IDENTITY POOL CONFIGURATION (Single mapping):
      //   Tag Key: cognito:groups
      //   Tag Value: claim:cognito:groups ? ':' + claim:cognito:groups.join('::') + ':' : ''
      //
      // EXAMPLE:
      //   User groups: ["ADMINS", "API_USERS"]
      //   Tag value: ":ADMINS::API_USERS:"
      //   Policy patterns: [":ADMINS:", ":API_USERS:"]
      //
      // BENEFITS:
      //   ✅ Single tag mapping (simple configuration)
      //   ✅ No false positives (":ADMIN:" won't match ":SUPER_ADMIN:")
      //   ✅ Exact group name matching
      //   ✅ Auto-scales with new groups

      // Create delimiter-wrapped patterns for exact matching
      const groupPatterns = groupConditions.map(
        (groupName) => `:${groupName}:`,
      );

      baseConditions['ForAnyValue:StringLike'] = {
        'cognito:groups': groupPatterns,
      };

      // DEBUG: Log the group conditions being created
      // eslint-disable-next-line no-console
      console.log(
        `🔧 StorageAccessPolicyFactory - Delimiter-based group conditions for groups [${groupConditions.join(', ')}]:`,
        {
          patterns: groupPatterns,
          condition: baseConditions,
        },
      );
    }

    switch (action) {
      case 'delete':
      case 'get':
      case 'write': {
        const resources = Array.from(s3Prefixes).map(
          (s3Prefix) => `${this.bucket.bucketArn}/${s3Prefix}`,
        );

        // DEBUG: Log the final resources for object-level actions
        // eslint-disable-next-line no-console
        console.log(
          `🔧 StorageAccessPolicyFactory - Object-level resources for "${action}":`,
          resources,
        );

        return new PolicyStatement({
          effect,
          actions: actionMap[action],
          resources,
          conditions:
            Object.keys(baseConditions).length > 0 ? baseConditions : undefined,
        });
      }
      case 'list': {
        const listConditions = {
          StringLike: {
            's3:prefix': Array.from(s3Prefixes).flatMap(toConditionPrefix),
          },
          ...baseConditions,
        };

        // DEBUG: Log the list conditions
        // eslint-disable-next-line no-console
        console.log(
          `🔧 StorageAccessPolicyFactory - List conditions:`,
          listConditions,
        );

        return new PolicyStatement({
          effect,
          actions: actionMap[action],
          resources: [this.bucket.bucketArn],
          conditions: listConditions,
        });
      }
    }
  };
}

const actionMap: Record<InternalStorageAction, string[]> = {
  get: ['s3:GetObject'],
  list: ['s3:ListBucket'],
  write: ['s3:PutObject'],
  delete: ['s3:DeleteObject'],
};

/**
 * Converts a prefix like foo/bar/* into [foo/bar/, foo/bar/*]
 * This is necessary to grant the ability to list all objects directly in "foo/bar" and all objects under "foo/bar"
 */
const toConditionPrefix = (prefix: StoragePath) => {
  const noTrailingWildcard = prefix.slice(0, -1);
  return [prefix, noTrailingWildcard];
};
