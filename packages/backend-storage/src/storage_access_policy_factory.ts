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

    const statements: PolicyStatement[] = [];

    permissions.forEach(
      (
        { allow: allowPrefixes, deny: denyPrefixes, groupConditions },
        action,
      ) => {
        if (allowPrefixes.size > 0) {
          // DEBUG: Log what we're about to create a statement for
          // eslint-disable-next-line no-console
          console.log(
            `🔧 StorageAccessPolicyFactory - Creating ALLOW statement for action "${action}":`,
            {
              allowPrefixes: Array.from(allowPrefixes),
              groupConditions,
            },
          );

          statements.push(
            this.getStatement(
              allowPrefixes,
              action,
              Effect.ALLOW,
              groupConditions,
            ),
          );
        }
        if (denyPrefixes.size > 0) {
          statements.push(
            this.getStatement(
              denyPrefixes,
              action,
              Effect.DENY,
              groupConditions,
            ),
          );
        }
      },
    );

    if (statements.length === 0) {
      // this could happen if the Map contained entries but all of the path sets were empty
      throw new AmplifyFault('EmptyPolicyFault', {
        message: 'At least one permission must be specified',
      });
    }

    const policy = new Policy(
      this.stack,
      `${this.stack.node.path}Access${this.stack.node.children.length}`,
      {
        statements,
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
      baseConditions['ForAnyValue:StringEquals'] = {
        'cognito:groups': groupConditions,
      };
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
