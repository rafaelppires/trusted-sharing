import random
import copy

def generate_dataset(ds_i, p, users, n):

    print("---> GENERATE DATASET ", ds_i)
    last_user = len(users)

    with open("ops_" + str(ds_i), 'w') as f:
        for i in range(n):
            v = random.randint(0,100)
            if (p != 0 and v <= p*100):
                # remove user
                r = random.randint(0, len(users) - 1)
                remove_user = users[r]
                f.write("remove," + remove_user + "\n")
                users.remove(remove_user)
            else:
                # add user
                new_user = u_name = "user" + str(last_user) + "@test.com"
                f.write("add," + new_user + "\n")
                last_user += 1

def generate_all():
    print("Generating synthetic data-sets")

    no_of_operations = 20
    no_of_initial_users = 100
    p_revoke = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1]

    # generate set of users
    users = []

    # write the initial users
    with open("members_" + str(no_of_initial_users), 'w') as f:
        for u in range (no_of_initial_users):
            u_name = "user" + str(u) + "@test.com"
            f.write(u_name + "\n")
            users.append(u_name)

    # write the different data-sets
    for i in range(len(p_revoke)):
        ds_users = copy.deepcopy(users)
        generate_dataset(i, p_revoke[i], ds_users, no_of_operations)


if __name__ == "__main__":
    generate_all()
