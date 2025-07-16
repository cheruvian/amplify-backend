import {
  AuthResources,
  AuthRoleName,
  ConstructFactoryGetInstanceProps,
  ResourceAccessAcceptor,
  ResourceAccessAcceptorFactory,
  ResourceProvider,
} from '@aws-amplify/plugin-types';
import { AmplifyUserError } from '@aws-amplify/platform-core';
import { EntityActionBuilder, StorageAccessBuilder } from './types.js';
import { entityIdSubstitution } from './constants.js';

export const roleAccessBuilder: StorageAccessBuilder = {
  authenticated: {
    to: (actions) => ({
      getResourceAccessAcceptors: [getAuthRoleResourceAccessAcceptor],
      uniqueDefinitionIdValidations: [
        {
          uniqueDefinitionId: `authenticated`,
          validationErrorOptions: {
            message: `Entity access definition for authenticated users specified multiple times.`,
            resolution: `Combine all access definitions for authenticated users on a single path into one access rule.`,
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
            message: `Entity access definition for guest users specified multiple times.`,
            resolution: `Combine all access definitions for guest users on a single path into one access rule.`,
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
            message: `Group access definition for groups [${groupNames.join(', ')}] specified multiple times.`,
            resolution: `Combine all access definitions for these groups on a single path into one access rule.`,
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
            message: `Entity access definition for ${entityId} specified multiple times.`,
            resolution: `Combine all access definitions for ${entityId} on a single path into one access rule.`,
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
              message: `Entity access definition for ${entityId} in groups [${groupNames.join(', ')}] specified multiple times.`,
              resolution: `Combine all access definitions for ${entityId} in these groups on a single path into one access rule.`,
            },
          },
        ],
        actions,
        idSubstitution: entityIdSubstitution,
        groupConditions: groupNames,
      }),
    }),
  }),
  resource: (other) => ({
    to: (actions) => ({
      getResourceAccessAcceptors: [
        (getInstanceProps: ConstructFactoryGetInstanceProps) =>
          other.getInstance(getInstanceProps).getResourceAccessAcceptor(),
      ],
      uniqueDefinitionIdValidations: [
        {
          uniqueDefinitionId: `resource`,
          validationErrorOptions: {
            message: `Resource access definition specified multiple times.`,
            resolution: `Combine all resource access definitions on a single path into one access rule.`,
          },
        },
      ],
      actions,
      idSubstitution: '*',
    }),
  }),
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
