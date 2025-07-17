import {
  ConstructFactoryGetInstanceProps,
  ResourceAccessAcceptor,
  SsmEnvironmentEntry,
} from '@aws-amplify/plugin-types';
import {
  StorageAccessBuilder,
  StorageAccessDefinition,
  StorageAccessGenerator,
  StoragePath,
} from './types.js';
import { entityIdPathToken, entityIdSubstitution } from './constants.js';
import { StorageAccessPolicyFactory } from './storage_access_policy_factory.js';
import { validateStorageAccessPaths as _validateStorageAccessPaths } from './validate_storage_access_paths.js';
import { roleAccessBuilder as _roleAccessBuilder } from './access_builder.js';
import {
  InternalStorageAction,
  StorageAccessConfig,
  StorageError,
} from './private_types.js';
import { AmplifyUserError } from '@aws-amplify/platform-core';

/* some types internal to this file to improve readability */

// Alias type for a string that is a ResourceAccessAcceptor token
type AcceptorToken = string;

// Callback function that places storagePath in the deny list for an action if it is not explicitly allowed by another rule
type SetDenyByDefault = (storagePath: StoragePath) => void;

/**
 * Orchestrates the process of converting customer-defined storage access rules into corresponding IAM policies
 * and attaching those policies to the corresponding IAM roles
 */
export class StorageAccessOrchestrator {
  /**
   * Maintains a mapping from a resource access acceptor to all of the access grants it has been configured with
   * Each entry of this map is fed into the policy generator to create a single policy for each acceptor
   */
  private acceptorAccessMap = new Map<
    AcceptorToken,
    {
      acceptor: ResourceAccessAcceptor;
      accessMap: Map<
        InternalStorageAction,
        {
          allow: Set<StoragePath>;
          deny: Set<StoragePath>;
          groupConditions?: string[];
        }
      >;
    }
  >();

  /**
   * Maintains pointers to the "deny" StoragePath Set for each access entry in the map above
   * This map is used during a final pass over all the StoragePaths to deny access on any paths where explicit allow rules were not specified
   */
  private prefixDenyMap = new Map<StoragePath, SetDenyByDefault[]>();

  /**
   * Instantiate with the access generator and other dependencies necessary for evaluating and constructing access policies
   * @param storageAccessGenerator The access callback defined by the customer
   * @param getInstanceProps props for fetching construct instances from the construct container
   * @param ssmEnvironmentEntries SSM context that should be passed to the ResourceAccessAcceptors when configuring access
   * @param policyFactory factory that generates IAM policies for various access control definitions
   * @param validateStorageAccessPaths validator function for checking access definition paths
   * @param roleAccessBuilder builder instance that is injected into the storageAccessGenerator to evaluate the rules
   */
  constructor(
    private readonly storageAccessGenerator: StorageAccessGenerator,
    private readonly getInstanceProps: ConstructFactoryGetInstanceProps,
    private readonly ssmEnvironmentEntries: SsmEnvironmentEntry[],
    private readonly policyFactory: StorageAccessPolicyFactory,
    private readonly validateStorageAccessPaths = _validateStorageAccessPaths,
    private readonly roleAccessBuilder: StorageAccessBuilder = _roleAccessBuilder,
  ) {}

  /**
   * Orchestrates the process of translating the customer-provided storage access rules into IAM policies and attaching those policies to the appropriate roles.
   *
   * The high level steps are:
   * 1. Invokes the storageAccessGenerator to produce a storageAccessDefinition
   * 2. Validates the paths in the storageAccessDefinition
   * 3. Organizes the storageAccessDefinition into internally managed maps to facilitate translation into allow / deny rules on IAM policies
   * 4. Invokes the policy generator to produce a policy with appropriate allow / deny rules
   * 5. Invokes the resourceAccessAcceptors for each entry in the storageAccessDefinition to accept the corresponding IAM policy
   */
  orchestrateStorageAccess = () => {
    // storageAccessGenerator is the access callback defined by the customer
    // here we inject the roleAccessBuilder into the callback and run it
    // this produces the access definition that will be used to create the storage policies
    const storageAccessDefinition = this.storageAccessGenerator(
      this.roleAccessBuilder,
    );

    // verify that the paths in the access definition are valid
    this.validateStorageAccessPaths(Object.keys(storageAccessDefinition));

    const storageOutputAccessDefinition: Record<string, StorageAccessConfig> =
      {};

    // iterate over the access definition and group permissions by ResourceAccessAcceptor
    Object.entries(storageAccessDefinition).forEach(
      ([s3Prefix, accessPermissions]) => {
        const uniqueDefinitionIdSet = new Set<string>();
        // iterate over all of the access definitions for a given prefix
        accessPermissions.forEach((permission) => {
          const accessConfig: StorageAccessConfig = {};
          // replace "read" with "get" and "list" in actions
          const replaceReadWithGetAndList = permission.actions.flatMap(
            (action) => (action === 'read' ? ['get', 'list'] : [action]),
          ) as InternalStorageAction[];

          // ensure the actions list has no duplicates
          const noDuplicateActions = Array.from(
            new Set(replaceReadWithGetAndList),
          );

          // iterate over all uniqueDefinitionIdValidations and ensure uniqueness within this path prefix
          permission.uniqueDefinitionIdValidations.forEach(
            ({ uniqueDefinitionId, validationErrorOptions }) => {
              if (uniqueDefinitionIdSet.has(uniqueDefinitionId)) {
                // Generate a helpful summary of all configurations for this path
                const configSummary = this.generateStorageConfigSummary(
                  s3Prefix,
                  accessPermissions,
                );

                // Enhanced error message with specific details about the duplicate
                const enhancedErrorOptions = {
                  ...validationErrorOptions,
                  message: `${validationErrorOptions.message}\n\nDuplicate found on storage path: '${s3Prefix}'\nDuplicate access definition ID: '${uniqueDefinitionId}'\nThis typically happens when you have multiple access rules for the same entity type on the same path.`,
                  details: `Storage path: ${s3Prefix}\nDuplicate definition: ${uniqueDefinitionId}\nActions in this permission: [${permission.actions.join(', ')}]\nID substitution: ${permission.idSubstitution}${permission.groupConditions ? `\nGroup conditions: [${permission.groupConditions.join(', ')}]` : ''}\n\nFull configuration summary for this path:\n${configSummary}`,
                };

                throw new AmplifyUserError<StorageError>(
                  'InvalidStorageAccessDefinitionError',
                  enhancedErrorOptions,
                );
              } else {
                uniqueDefinitionIdSet.add(uniqueDefinitionId);
              }

              accessConfig[uniqueDefinitionId] = noDuplicateActions;
            },
          );
          // make the owner placeholder substitution in the s3 prefix
          const prefix = placeholderSubstitution(
            s3Prefix,
            permission.idSubstitution,
          );

          storageOutputAccessDefinition[prefix] = {
            ...storageOutputAccessDefinition[prefix],
            ...accessConfig,
          };

          // set an entry that maps this permission to each resource acceptor
          permission.getResourceAccessAcceptors.forEach(
            (getResourceAccessAcceptor) => {
              this.addAccessDefinition(
                getResourceAccessAcceptor(this.getInstanceProps),
                noDuplicateActions,
                prefix,
                permission.groupConditions,
              );
            },
          );
        });
      },
    );

    // iterate over the access map entries and invoke each ResourceAccessAcceptor to accept the permissions
    this.attachPolicies(this.ssmEnvironmentEntries);

    return storageOutputAccessDefinition;
  };

  /**
   * Generates a helpful summary of all storage access configurations for a given path
   * to help developers understand what configurations are conflicting
   */
  private generateStorageConfigSummary = (
    s3Prefix: string,
    accessPermissions: StorageAccessDefinition[],
  ): string => {
    const summary = [
      `Storage path: '${s3Prefix}'`,
      `Total access rules: ${accessPermissions.length}`,
      '',
    ];

    accessPermissions.forEach((permission, index) => {
      const ruleNumber = index + 1;
      summary.push(`Rule ${ruleNumber}:`);
      summary.push(`  Actions: [${permission.actions.join(', ')}]`);
      summary.push(`  ID substitution: ${permission.idSubstitution}`);

      if (permission.groupConditions && permission.groupConditions.length > 0) {
        summary.push(
          `  Group conditions: [${permission.groupConditions.join(', ')}]`,
        );
      }

      // Try to identify the access type from the unique definition IDs
      const definitionIds = permission.uniqueDefinitionIdValidations.map(
        (v) => v.uniqueDefinitionId,
      );
      const accessType = this.identifyAccessType(definitionIds[0] || 'unknown');
      summary.push(`  Access type: ${accessType}`);
      summary.push(`  Definition IDs: [${definitionIds.join(', ')}]`);
      summary.push('');
    });

    summary.push('💡 To fix duplicate access definitions:');
    summary.push(
      '   Combine multiple rules for the same access type into a single rule with all required actions.',
    );
    summary.push(
      "   Example: allow.authenticated.to(['read', 'write']) instead of separate rules.",
    );

    return summary.join('\n');
  };

  /**
   * Helper to identify the human-readable access type from a definition ID
   */
  private identifyAccessType = (definitionId: string): string => {
    if (definitionId === 'authenticated') return 'Authenticated users';
    if (definitionId === 'guest') return 'Guest users';
    if (definitionId.startsWith('groups')) return 'User groups';
    if (definitionId.startsWith('entity') && definitionId.includes('InGroups'))
      return 'Entity with group restrictions';
    if (definitionId.startsWith('entity')) return 'Entity access';
    if (definitionId === 'resource') return 'Resource access';
    return definitionId;
  };

  /**
   * Add an entry to the internal acceptorAccessMap and prefixDenyMap.
   * This entry defines a set of actions on a single s3 prefix that should be attached to a given ResourceAccessAcceptor
   */
  private addAccessDefinition = (
    resourceAccessAcceptor: ResourceAccessAcceptor,
    actions: InternalStorageAction[],
    s3Prefix: StoragePath,
    groupConditions?: string[],
  ) => {
    const acceptorToken = resourceAccessAcceptor.identifier;

    // if we haven't seen this token before, add it to the map
    if (!this.acceptorAccessMap.has(acceptorToken)) {
      this.acceptorAccessMap.set(acceptorToken, {
        accessMap: new Map(),
        acceptor: resourceAccessAcceptor,
      });
    }
    const accessMap = this.acceptorAccessMap.get(acceptorToken)!.accessMap;
    // add each action to the accessMap for this acceptorToken
    actions.forEach((action) => {
      if (!accessMap.has(action)) {
        // if we haven't seen this action for this acceptorToken before, add it to the map
        const allowSet = new Set<StoragePath>([s3Prefix]);
        const denySet = new Set<StoragePath>();
        accessMap.set(action, {
          allow: allowSet,
          deny: denySet,
          groupConditions,
        });

        // this is where we create the reverse mapping that allows us to add entries to the denySet later by looking up the prefix
        this.setPrefixDenyMapEntry(s3Prefix, allowSet, denySet);
      } else {
        // otherwise add the prefix to the existing allow set
        const { allow: allowSet, deny: denySet } = accessMap.get(action)!;
        allowSet.add(s3Prefix);

        // add an entry in the prefixDenyMap for the existing allow and deny set
        this.setPrefixDenyMapEntry(s3Prefix, allowSet, denySet);
      }
    });
  };

  /**
   * Iterates over all of the access definitions that have been added to the orchestrator,
   * generates a policy for each accessMap,
   * and attaches the policy to the corresponding ResourceAccessAcceptor
   *
   * After this method is called, the existing access definition state is cleared.
   * This prevents multiple calls to this method from producing duplicate policies.
   * The class can continue to be used to build up state for a new set of policies if desired.
   * @param ssmEnvironmentEntries Additional SSM context that is passed to each ResourceAccessAcceptor
   */
  private attachPolicies = (ssmEnvironmentEntries: SsmEnvironmentEntry[]) => {
    const allPaths = Array.from(this.prefixDenyMap.keys());
    allPaths.forEach((storagePath) => {
      const parent = findParent(storagePath, allPaths);
      // do not add to prefix deny map if there is no parent or the path is a subpath with entity id
      if (
        !parent ||
        parent === storagePath.replaceAll(`${entityIdSubstitution}/`, '')
      ) {
        return;
      }
      // if a parent path is defined, invoke the denyByDefault callback on this subpath for all policies that exist on the parent path
      this.prefixDenyMap
        .get(parent)
        ?.forEach((denyByDefaultCallback) =>
          denyByDefaultCallback(storagePath),
        );
    });

    this.acceptorAccessMap.forEach(({ acceptor, accessMap }) => {
      // removing subpaths from the allow set prevents unnecessary paths from being added to the policy
      // for example, if there are allow read rules for /foo/* and /foo/bar/* we only need to add /foo/* to the policy because that includes /foo/bar/*
      accessMap.forEach(({ allow }) => {
        removeSubPathsFromSet(allow);
      });
      acceptor.acceptResourceAccess(
        this.policyFactory.createPolicy(accessMap),
        ssmEnvironmentEntries,
      );
    });
    this.acceptorAccessMap.clear();
    this.prefixDenyMap.clear();
  };

  private setPrefixDenyMapEntry = (
    storagePath: StoragePath,
    allowPathSet: Set<StoragePath>,
    denyPathSet: Set<StoragePath>,
  ) => {
    // function that will add the denyPath to the denyPathSet unless the allowPathSet explicitly allows the path
    const setDenyByDefault = (denyPath: StoragePath) => {
      if (!allowPathSet.has(denyPath)) {
        denyPathSet.add(denyPath);
      }
    };
    if (!this.prefixDenyMap.has(storagePath)) {
      this.prefixDenyMap.set(storagePath, [setDenyByDefault]);
    } else {
      this.prefixDenyMap.get(storagePath)?.push(setDenyByDefault);
    }
  };
}

/**
 * This factory is really only necessary for allowing us to mock the StorageAccessOrchestrator in tests
 */
export class StorageAccessOrchestratorFactory {
  getInstance = (
    storageAccessGenerator: StorageAccessGenerator,
    getInstanceProps: ConstructFactoryGetInstanceProps,
    ssmEnvironmentEntries: SsmEnvironmentEntry[],
    policyFactory: StorageAccessPolicyFactory,
  ) =>
    new StorageAccessOrchestrator(
      storageAccessGenerator,
      getInstanceProps,
      ssmEnvironmentEntries,
      policyFactory,
    );
}

/**
 * Performs the owner placeholder substitution in the s3 prefix
 */
const placeholderSubstitution = (
  s3Prefix: string,
  idSubstitution: string,
): StoragePath => {
  const prefix = s3Prefix.replaceAll(
    entityIdPathToken,
    idSubstitution,
  ) as StoragePath;

  // for owner paths where prefix ends with '/*/*' remove the last wildcard
  if (prefix.endsWith('/*/*')) {
    return prefix.slice(0, -2) as StoragePath;
  }

  return prefix as StoragePath;
};

/**
 * Returns the element in paths that is a prefix of path, if any
 * Note that there can only be one at this point because of upstream validation
 */
const findParent = (path: string, paths: string[]) =>
  paths.find((p) => path !== p && path.startsWith(p.replaceAll('*', ''))) as
    | StoragePath
    | undefined;

const removeSubPathsFromSet = (paths: Set<StoragePath>) => {
  paths.forEach((path) => {
    if (findParent(path, Array.from(paths))) {
      paths.delete(path);
    }
  });
};
