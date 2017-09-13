'''
  Implementation of SP-IBBE,
  i.e. Secured & Partitioned - Identity Based Broadcast Encryption.

  Author: Stefan Contiu <stefan.contiu@u-bordeaux.fr>

  Published under Apache v2 License:
        https://www.apache.org/licenses/LICENSE-2.0.txt

  Remark(s):
        This file holds high level operations of the SP-IBBE scheme.
        The administrators have a HONEST-BUT-CURIOUS trust model, meaning they
        will execute what is asked from them but without confidentiality
        guarantees.
'''

import numpy as np

MAX_USERS_PER_PARTITION = 1000


def add_user_to_group(user_name, group_name):
    # 1. get partition id
    partition_id = compute_partition_id(user_name, group_name)

    # 2. get [Members List] and [C1, C2]
    members = []
    g_meta = []

    # 3. append new member
    members.append(user_name)

    # 4. modify C2

    # 5. get a signed hash of new data

    # 6. push to cloud

    pass

def remove_user_from_group(user_name, group_name):
    pass

def compute_partition_id(user_name, group_name):
    gp = GroupPartitionsMeta()

    # do we need more partitions for the group ?
    current_free_space = gp.get_remaining_space(group_name);
    if (current_free_space < free_space_treshold):
        # add some more partitions

    # weighted sampling
    partitions = range(partitions_count)
    weights = gp.group_free_space_histogram(group_name)
    i = np.random.choice(vec,size=1,replace=False, p=partitions)

    return group_name + "_" + i

class GroupPartitionsMeta:

    group_free_space = dict()

    user_partitions = dict()

    group_partitions_count = dict()

    def __init__(self, arg):
        pass

    def get_remaining_space(self, group):
        # if group_free_space does not have group, create partition table
        return group_free_space[group]

    def add_partitions(self, group_name, new_partitions_count):
        # add

    def group_free_space_histogram(self, group_name):
        # todo this method should be modified to return percents
        return group_partitions_count[group_name]

def main():
    generate_partition_id("stefan.contiu@gmail.com", "friends")

if __name__ == "__main__":
    main()
