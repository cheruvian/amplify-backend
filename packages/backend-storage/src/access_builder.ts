import {
  AuthResources,
  AuthRoleName,
  ConstructFactory,
  ConstructFactoryGetInstanceProps,
  ResourceAccessAcceptor,
  ResourceAccessAcceptorFactory,
  ResourceProvider,
} from '@aws-amplify/plugin-types';
import { AmplifyUserError } from '@aws-amplify/platform-core';
import { EntityActionBuilder, StorageAccessBuilder } from './types.js';
import { entityIdSubstitution } from './constants.js';

// WeakMap to track unique identifiers for each resource
const resourceIdentifierMap = new WeakMap<
  ConstructFactory<ResourceProvider & ResourceAccessAcceptorFactory>,
  string
>();
let resourceCounter = 0;

const getResourceIdentifier = (
  resource: ConstructFactory<ResourceProvider & ResourceAccessAcceptorFactory>,
): string => {
  if (!resourceIdentifierMap.has(resource)) {
    resourceIdentifierMap.set(resource, `resource_${++resourceCounter}`);
  }
  return resourceIdentifierMap.get(resource)!;
};

export const roleAccessBuilder: StorageAccessBuilder = {
  authenticated: {
    to: (actions) => ({
      getResourceAccessAcceptors: [getAuthRoleResourceAccessAcceptor],
      uniqueDefinitionIdValidations: [
        {
          uniqueDefinitionId: `authenticated`,
          validationErrorOptions: {
            message: `Storage access definition for authenticated users specified multiple times on the same path.`,
            resolution: `Combine all access definitions for authenticated users on a single path into one access rule. For example, instead of:\n  'path/*': [\n    allow.authenticated.to(['read']),\n    allow.authenticated.to(['write'])\n  ]\nUse:\n  'path/*': [\n    allow.authenticated.to(['read', 'write'])\n  ]`,
            details: `Access type: authenticated users\nActions requested: [${actions.join(', ')}]`,
          },
        },
      ],
      actions,
      idSubstitution: '*',
    }),
  },
  guest: {
    to: (actions) => ({
      getResourceAccessAcceptors: [getUnauthRoleResourceAccessAcceptor],
      uniqueDefinitionIdValidations: [
        {
          uniqueDefinitionId: `guest`,
          validationErrorOptions: {
            message: `Storage access definition for guest users specified multiple times on the same path.`,
            resolution: `Combine all access definitions for guest users on a single path into one access rule. For example, instead of:\n  'path/*': [\n    allow.guest.to(['read']),\n    allow.guest.to(['write'])\n  ]\nUse:\n  'path/*': [\n    allow.guest.to(['read', 'write'])\n  ]`,
            details: `Access type: guest users\nActions requested: [${actions.join(', ')}]`,
          },
        },
      ],
      actions,
      idSubstitution: '*',
    }),
  },
  groups: (groupNames) => ({
    to: (actions) => ({
      getResourceAccessAcceptors: [
        createGroupsResourceAccessAcceptor(groupNames),
      ],
      uniqueDefinitionIdValidations: [
        {
          uniqueDefinitionId: `groups${groupNames.join('')}`,
          validationErrorOptions: {
            message: `Storage access definition for groups [${groupNames.join(', ')}] specified multiple times on the same path.`,
            resolution: `Combine all access definitions for these groups on a single path into one access rule. For example, instead of:\n  'path/*': [\n    allow.groups(['${groupNames.join("', '")}]).to(['read']),\n    allow.groups(['${groupNames.join("', '")}]).to(['write'])\n  ]\nUse:\n  'path/*': [\n    allow.groups(['${groupNames.join("', '")}]).to(['read', 'write'])\n  ]`,
            details: `Access type: groups [${groupNames.join(', ')}]\nActions requested: [${actions.join(', ')}]\nGroup count: ${groupNames.length}`,
          },
        },
      ],
      actions,
      idSubstitution: '*', // Groups get wildcard access
      groupConditions: groupNames,
    }),
  }),
  entity: (entityId): EntityActionBuilder => ({
    to: (actions) => ({
      getResourceAccessAcceptors: [getAuthRoleResourceAccessAcceptor],
      uniqueDefinitionIdValidations: [
        {
          uniqueDefinitionId: `entity${entityId}`,
          validationErrorOptions: {
            message: `Storage access definition for entity '${entityId}' specified multiple times on the same path.`,
            resolution: `Combine all access definitions for entity '${entityId}' on a single path into one access rule. For example, instead of:\n  'path/{entity_id}/*': [\n    allow.entity('${entityId}').to(['read']),\n    allow.entity('${entityId}').to(['write'])\n  ]\nUse:\n  'path/{entity_id}/*': [\n    allow.entity('${entityId}').to(['read', 'write'])\n  ]`,
            details: `Access type: entity '${entityId}'\nActions requested: [${actions.join(', ')}]\nID substitution: ${entityIdSubstitution}`,
          },
        },
      ],
      actions,
      idSubstitution: entityIdSubstitution,
    }),
    inGroups: (groupNames) => ({
      to: (actions) => ({
        getResourceAccessAcceptors: [
          createGroupsResourceAccessAcceptor(groupNames),
        ],
        uniqueDefinitionIdValidations: [
          {
            uniqueDefinitionId: `entity${entityId}InGroups${groupNames.join('')}`,
            validationErrorOptions: {
              message: `Storage access definition for entity '${entityId}' in groups [${groupNames.join(', ')}] specified multiple times on the same path.`,
              resolution: `Combine all access definitions for entity '${entityId}' in these groups on a single path into one access rule. For example, instead of:\n  'path/{entity_id}/*': [\n    allow.entity('${entityId}').inGroups(['${groupNames.join("', '")}]).to(['read']),\n    allow.entity('${entityId}').inGroups(['${groupNames.join("', '")}]).to(['write'])\n  ]\nUse:\n  'path/{entity_id}/*': [\n    allow.entity('${entityId}').inGroups(['${groupNames.join("', '")}]).to(['read', 'write'])\n  ]`,
              details: `Access type: entity '${entityId}' restricted to groups [${groupNames.join(', ')}]\nActions requested: [${actions.join(', ')}]\nGroup restrictions: ${groupNames.length} groups\nID substitution: ${entityIdSubstitution}`,
            },
          },
        ],
        actions,
        idSubstitution: entityIdSubstitution,
        groupConditions: groupNames,
      }),
    }),
  }),
  resource: (other) => {
    const resourceId = getResourceIdentifier(other);
    return {
      to: (actions) => ({
        getResourceAccessAcceptors: [
          (getInstanceProps: ConstructFactoryGetInstanceProps) =>
            other.getInstance(getInstanceProps).getResourceAccessAcceptor(),
        ],
        uniqueDefinitionIdValidations: [
          {
            uniqueDefinitionId: resourceId,
            validationErrorOptions: {
              message: `Storage access definition for this specific resource specified multiple times on the same path.`,
              resolution: `Combine all access definitions for this specific resource on a single path into one access rule. For example, instead of:\n  'path/*': [\n    allow.resource(myFunction).to(['read']),\n    allow.resource(myFunction).to(['write'])\n  ]\nUse:\n  'path/*': [\n    allow.resource(myFunction).to(['read', 'write'])\n  ]\n\nNote: Different resources can have separate access rules on the same path.`,
              details: `Access type: resource access\nActions requested: [${actions.join(', ')}]\nResource identifier: ${resourceId}`,
            },
          },
        ],
        actions,
        idSubstitution: '*',
      }),
    };
  },
};

const getAuthRoleResourceAccessAcceptor = (
  getInstanceProps: ConstructFactoryGetInstanceProps,
) => {
  return getUserRoleResourceAccessAcceptor(
    getInstanceProps,
    'authenticatedUserIamRole',
  );
};

const getUnauthRoleResourceAccessAcceptor = (
  getInstanceProps: ConstructFactoryGetInstanceProps,
) => {
  return getUserRoleResourceAccessAcceptor(
    getInstanceProps,
    'unauthenticatedUserIamRole',
  );
};

/**
 * Creates a properly typed function that validates group compatibility and returns a resource access acceptor
 */
const createGroupsResourceAccessAcceptor = (
  groupNames: string[],
): ((
  getInstanceProps: ConstructFactoryGetInstanceProps,
) => ResourceAccessAcceptor) => {
  return (getInstanceProps: ConstructFactoryGetInstanceProps) => {
    const authConstruct = getInstanceProps.constructContainer
      .getConstructFactory<
        ResourceProvider<AuthResources> &
          ResourceAccessAcceptorFactory<AuthRoleName | string>
      >('AuthResources')
      ?.getInstance(getInstanceProps);

    if (!authConstruct) {
      throw new Error(
        `Cannot specify auth access for groups without defining auth. See https://docs.amplify.aws/gen2/build-a-backend/auth/set-up-auth/ for more information.`,
      );
    }

    // Check if any of the specified groups have dedicated roles assigned
    // This would conflict with our conditional access approach
    const groupsWithRoles = groupNames.filter(
      (groupName) => authConstruct.resources.groups?.[groupName]?.role,
    );

    if (groupsWithRoles.length > 0) {
      throw new AmplifyUserError('IncompatibleGroupRolesError', {
        message: `Groups [${groupsWithRoles.join(', ')}] have dedicated IAM roles assigned, which is incompatible with conditional storage access.`,
        resolution: `Remove the role assignments from these User Pool groups, or use storage access that doesn't rely on group conditions. When groups have dedicated roles, users assume those roles instead of the base authenticated role where conditional policies are attached.`,
        details: `🔄 MIGRATION GUIDE for group-entities changes:\n\nThis error occurs because you have User Pool groups with dedicated IAM roles, but the new storage access system uses conditional policies on the base authenticated role instead.\n\nTo fix this:\n1. Remove role assignments from groups: [${groupsWithRoles.join(', ')}]\n2. Groups will now use conditional access on the authenticated role\n3. This provides better security and more granular control\n\n📋 What changed:\n• Groups no longer get individual IAM roles by default\n• Group access is now handled through conditional policies\n• Entity access can be restricted to specific groups\n• Better support for fine-grained permissions\n\n🛠️ Example migration:\nBEFORE: Group had dedicated role + storage access\nAFTER: Group uses conditional access on authenticated role\n\nFor more details, see the storage access documentation.`,
      });
    }

    return authConstruct.getResourceAccessAcceptor('authenticatedUserIamRole');
  };
};

const getUserRoleResourceAccessAcceptor = (
  getInstanceProps: ConstructFactoryGetInstanceProps,
  roleName: AuthRoleName | string,
) => {
  const resourceAccessAcceptor = getInstanceProps.constructContainer
    .getConstructFactory<
      ResourceProvider & ResourceAccessAcceptorFactory<AuthRoleName | string>
    >('AuthResources')
    ?.getInstance(getInstanceProps)
    .getResourceAccessAcceptor(roleName);
  if (!resourceAccessAcceptor) {
    throw new Error(
      `Cannot specify auth access for ${
        roleName as string
      } users without defining auth. See https://docs.amplify.aws/gen2/build-a-backend/auth/set-up-auth/ for more information.`,
    );
  }
  return resourceAccessAcceptor;
};
